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

    // Always derive the interface name through the same production mapping used by VPNClient.
    const interfaceName = `${Constants.VC_INTF_PREFIX}${profileId}`;

    if (/^[A-Za-z0-9_.-]{1,15}$/.test(interfaceName)) {
      return execFile('ip', ['link', 'show', 'dev', interfaceName])
        .then(() => true)
        .catch((err) => {
          // ip link show returns 1 when the requested device does not exist.
          // Other exit codes indicate invocation/environment errors and are indeterminate.
          if (err && err.code === 1)
            return false;
          return null;
        });
    }

    // Legacy profile IDs can predate the current ten-character validation. The derived
    // interface name is therefore too long for a direct `ip link show dev NAME` lookup.
    // Enumerate the interface table and compare the exact production-derived name instead
    // of truncating or otherwise inventing a different interface name.
    return execFile('ip', ['-o', 'link', 'show'])
      .then(result => {
        const interfaceExists = result.stdout
          .split('\n')
          .map(line => line.trim())
          .filter(Boolean)
          .some(line => {
            const match = line.match(/^\d+:\s+([^:]+):/);
            if (!match)
              return false;
            return match[1].split('@', 1)[0] === interfaceName;
          });
        return interfaceExists;
      })
      .catch(() => null);
  }
