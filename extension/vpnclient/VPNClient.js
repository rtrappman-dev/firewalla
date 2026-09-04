/*    Copyright 2016-2026 Firewalla Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

'use strict';

const net = require('net')
const path = require('path');
const { exec, execFile } = require('child-process-promise');
const log = require('../../net2/logger.js')(__filename);
const fc = require('../../net2/config.js');
const f = require('../../net2/Firewalla.js');
const fs = require('fs');
const Promise = require('bluebird');
Promise.promisifyAll(fs);
const sem = require('../../sensor/SensorEventManager.js').getInstance();
const _ = require('lodash');
const sclient = require('../../util/redis_manager.js').getSubscriptionClient();
const vpnClientEnforcer = require('./VPNClientEnforcer.js');
const routing = require('../routing/routing.js');
const { Rule } = require('../../net2/Iptables.js');
const iptc = require('../../control/IptablesControl.js');
const { Address4, Address6 } = require('ip-address');
const sysManager = require('../../net2/SysManager');
const ipTool = require('ip');
const Ipset = require('../../net2/Ipset.js');
const PlatformLoader = require('../../platform/PlatformLoader.js');
const { rclient } = require('../../util/redis_manager.js');
const Constants = require('../../net2/Constants.js');
const AsyncLock = require('../../vendor_lib/async-lock');
const lock = new AsyncLock();
const platform = PlatformLoader.getPlatform()
const fireRouter = require('../../net2/FireRouter.js');
const scheduler = require('../../util/scheduler.js');
const envCreatedMap = {};
const INTERNET_ON_OFF_THRESHOLD = 2;

const instances = {};

class VPNClient {
  constructor(options) {
    const profileId = options.profileId;
    this.isFirstLaunch = true; // should be only true when first created
    if (!profileId)
      return null;
    VPNClient.validateProfileId(profileId);
    if (!instances[profileId]) {
      instances[profileId] = this;
      this.profileId = profileId;
      if (f.isMain()) {
        this.internetFailureCount = INTERNET_ON_OFF_THRESHOLD - 1;
        this.internetSuccessCount = INTERNET_ON_OFF_THRESHOLD - 1;
        this.hookLinkStateChange();
        this.hookSettingsChange();

        setInterval(() => {
          this._checkConnectivity().catch((err) => {
            log.error(`Failed to check connectivity on VPN client ${this.profileId}`, err.message);
          });
        }, 30000);

        if (this._getRedisRouteUpdateMessageChannel()) {
          const channel = this._getRedisRouteUpdateMessageChannel();
          sclient.on("message", (c, message) => {
            if (c === channel && message === this.profileId) {
              log.info(`VPN client ${this.profileId} route is updated, will refresh routes ...`);
              this._scheduleRefreshRoutes();
              // emit link established event immediately
              if (this._started) {
                sem.emitEvent({
                  type: "link_established",
                  profileId: this.profileId,
                  routeUpdated: true,
                  suppressEventLogging: true,
                });
              }
            }
          });
          sclient.subscribe(channel);
        }
      }
    }
    return instances[profileId];
  }

  static validateProfileId(profileId) {
    if (!_.isString(profileId) || !/^[a-zA-Z0-9_]{1,10}$/.test(profileId)) {
      throw new Error("'profileId' should only contain alphanumeric letters or underscore and no longer than 10 characters");
    }
    return profileId;
  }

  static isValidFirewallaDDNSDomain(domain) {
    if (!_.isString(domain) || domain.length === 0 || domain.length > 253)
      return false;

    const labels = domain.split('.');
    if (labels.some(label => label.length === 0 || label.length > 63))
      return false;

    return /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*(?:firewalla\.org|firewalla\.com)$/i.test(domain);
  }

  static getInstance(profileId) {
    if (instances.hasOwnProperty(profileId))
      return instances[profileId];
    else
      return null;
  }

  static async isProfileActive(profileId) {
    const instance = VPNClient.getInstance(profileId);
    if (instance && instance.isStarted())
      return true;

    const cachedState = await rclient.getAsync(VPNClient.getStateCacheKey(profileId)).catch(() => null);
    if (cachedState === "true")
      return true;

    // A cached false state is not sufficient by itself after a restart. Verify that
    // the derived VPN interface is actually absent before declaring a legacy profile inactive.
    const interfaceName = `${Constants.VC_INTF_PREFIX}${profileId}`;
    if (/^[A-Za-z0-9_.-]{1,15}$/.test(interfaceName)) {
      return execFile('ip', ['link', 'show', 'dev', interfaceName])
        .then(() => true)
        .catch((err) => {
          if (err && err.code === 1)
            return false;
          return null;
        });
    }

    // Legacy profile IDs can predate the current ten-character validation and therefore
    // may map to an interface name that cannot be queried as a single argv value. Enumerate
    // the interface table instead and look for the exact production-derived name.
    return execFile('ip', ['-o', 'link', 'show'])
      .then(result => {
        const names = result.stdout
          .split('\n')
          .map(line => line.trim())
          .filter(Boolean)
          .map(line => line.replace(/^\d+:\s+/, '').split(':', 1)[0].split('@', 1)[0]);
        return names.includes(interfaceName);
      })
      .catch(() => null);
  }

  static async getVPNProfilesForInit() {
    const types = ["openvpn", "wireguard", "amneziawg", "ssl", "zerotier", "nebula", "trojan", "clash", "hysteria", "gost", "ipsec", "ts"];
    const results = {}
    await Promise.all(types.map(async (type) => {
      const c = this.getClass(type);
      if (c) {
        let profiles = [];
        const profileIds = await c.listProfileIds();
        const profileResults = await Promise.all(profileIds.map(async (profileId) => {
          try {
            VPNClient.validateProfileId(profileId);
          } catch (err) {
            log.error(`Skipping invalid VPN client profile ${profileId} during initialization`, err.message);
            return null;
          }

          return await new c({ profileId: profileId }).getAttributes();
        }));
        Array.prototype.push.apply(profiles, profileResults.filter(Boolean));
        results[c.getKeyNameForInit()] = profiles;
      }
    }));
    return results
  }

  static getClass(type) {
    if (!type) {
      throw new Error("type should be specified");
    }
    switch (type) {
      case "openvpn": {
        return require('./OpenVPNClient.js');
      }
      case "wireguard": {
        return require('./WGVPNClient.js');
      }
      case "amneziawg": {
        return require('./AmneziaWGVPNClient.js');
      }
      case "ssl": {
        if (platform.isDockerSupported()) {
          return require('./docker/OCDockerClient.js');
        } else {
          return require('./OCVPNClient.js');
        }
      }
      case "zerotier": {
        return require('./docker/ZTDockerClient.js');
      }
      case "trojan": {
        return require('./docker/TrojanDockerClient.js');
      }
      case "nebula": {
        return require('./docker/NebulaDockerClient.js');
      }
      case "ipsec": {
        return require('./docker/IPSecDockerClient.js');
      }
      case "clash": {
        return require('./docker/ClashDockerClient.js');
      }
      case "hysteria": {
        return require('./docker/HysteriaDockerClient.js');
      }
      case "gost": {
        return require('./docker/GostDockerClient.js');
      }
      case "ts": {
        return require('./docker/TSDockerClient.js');
      }
      default:
        throw new Error(`Unrecognized VPN client type: ${type}`);
    }
  }

  _getRedisRouteUpdateMessageChannel() {
    return null;
  }

  static getProtocol() {
    return null;
  }

  static getKeyNameForInit() {
    return "";
  }

  static getDnsMarkTag(profileId) {
    return `vc_${profileId}`;
  }
