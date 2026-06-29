let lastAlertSignature = null;
let lastSafeSignature = null;
let lastMaliciousSignature = null;
let lastNetworkSignature = null;
let hasInitializedAlertState = false;

function showPopup(message, danger = false) {

    const popup = document.getElementById('popup');
    const content = document.getElementById('popup-content');

    if (!popup || !content) return;

    content.textContent = message;

    popup.classList.remove('hidden');
    popup.classList.toggle('danger', danger);
    popup.classList.toggle('success', !danger);

    setTimeout(() => {
        popup.classList.add('hidden');
    }, 4000);
}



async function refreshNetworkLogs() {

    try {

        const response = await fetch('/api/network/logs');
        const data = await response.json();

        const table = document.getElementById("network-logs-body");

        if (!table) return;

        table.innerHTML = "";

        if (!data.logs || data.logs.length === 0) {

            table.innerHTML =
                `<tr><td colspan="4">No network attacks detected.</td></tr>`;

        } else {

            data.logs.forEach(log => {

                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>${log.attacker}</td>
                    <td>${log.destination}</td>
                    <td>${log.type}</td>
                    <td>${log.time}</td>
                `;

                table.appendChild(row);

            });

        }

    } catch (error) {

        console.error("Network log refresh error:", error);

    }

}



async function refreshBlockedIPs() {

    try {

        const response = await fetch('/api/network/blocked');
        const data = await response.json();

        const table = document.getElementById("blocked-ip-body");

        if (!table) return;

        table.innerHTML = "";

        if (!data.blocked_ips || data.blocked_ips.length === 0) {

            table.innerHTML =
                `<tr><td colspan="2">No blocked IPs</td></tr>`;

        } else {

            data.blocked_ips.forEach(ip => {

                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>${ip.ip}</td>
                    <td>${ip.time.replace(" GMT","")}</td>
                `;

                table.appendChild(row);

            });

        }

    } catch (error) {

        console.error("Blocked IP refresh error:", error);

    }

}



async function checkNetworkAlert() {

    try {

        const response = await fetch('/api/network/blocked');
        const data = await response.json();

        if (data.blocked_ips && data.blocked_ips.length > 0) {

            const latest = data.blocked_ips[0];
            const signature = `${latest.ip}|${latest.time}`;

            if (!hasInitializedAlertState) {

                lastNetworkSignature = signature;

            } else if (lastNetworkSignature !== signature) {

                lastNetworkSignature = signature;

                showPopup(
                    `🚨 Network Attack Blocked!\nIP: ${latest.ip}\nAction: Firewall blocked attacker`,
                    true
                );

            }

        }

    } catch (error) {

        console.error("Network IDS alert error:", error);

    }

}



async function refreshDashboard() {

    try {

        const response = await fetch('/api/status');
        const data = await response.json();

        const monitorStatus = document.getElementById('monitor-status');
        const totalEvents = document.getElementById('total-events');
        const blockedCount = document.getElementById('blocked-count');
        const devicesBody = document.getElementById('devices-body');

        if (monitorStatus) monitorStatus.textContent = data.monitor_status;
        if (totalEvents) totalEvents.textContent = data.total_events;
        if (blockedCount) blockedCount.textContent = data.blocked_count;

        if (devicesBody) {

            devicesBody.innerHTML = '';

            if (!data.connected_devices || data.connected_devices.length === 0) {

                devicesBody.innerHTML =
                    '<tr><td colspan="5">No USB devices connected.</td></tr>';

            } else {

                data.connected_devices.forEach(device => {

                    const row = document.createElement('tr');

                    row.innerHTML = `
                        <td>${device.device}</td>
                        <td>${device.mountpoint}</td>
                        <td>${device.fstype}</td>
                        <td>${device.options}</td>
                        <td>${device.is_blocked ? 'BLOCKED' : 'OPEN'}</td>
                    `;

                    devicesBody.appendChild(row);

                });

            }

        }

        await refreshNetworkLogs();
        await refreshBlockedIPs();
        await checkNetworkAlert();

        hasInitializedAlertState = true;

    } catch (error) {

        console.error('Dashboard refresh error:', error);

    }

}



async function controlMonitor(endpoint) {

    const statusElement = document.getElementById('action-status');

    try {

        const response = await fetch(endpoint, { method: 'POST' });
        const result = await response.json();

        if (statusElement)
            statusElement.textContent = result.status;

        await refreshDashboard();

    } catch (error) {

        if (statusElement)
            statusElement.textContent = 'Failed to update monitor state.';

    }

}



document.addEventListener("DOMContentLoaded", () => {

    const startUSB = document.getElementById('start-monitor-btn');
    const stopUSB = document.getElementById('stop-monitor-btn');
    const startNet = document.getElementById('start-network-btn');
    const stopNet = document.getElementById('stop-network-btn');

    if (startUSB)
        startUSB.addEventListener('click', () => {
            controlMonitor('/api/monitor/start');
        });

    if (stopUSB)
        stopUSB.addEventListener('click', () => {
            controlMonitor('/api/monitor/stop');
        });

    if (startNet)
        startNet.addEventListener('click', () => {
            controlMonitor('/api/network/start');
        });

    if (stopNet)
        stopNet.addEventListener('click', () => {
            controlMonitor('/api/network/stop');
        });

    refreshDashboard();
    setInterval(refreshDashboard, 3000);

});