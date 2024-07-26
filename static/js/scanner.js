document.addEventListener("DOMContentLoaded", function() {
    var socket = io();
    var openPorts = [];
    var scanResults = [];

    // IP 주소 또는 도메인 형식 검사 함수
    function isValidIPorDomain(ip) {
        var ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        var domainPattern = /^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9\-]{1,61}[a-zA-Z0-9])\.?)+[a-zA-Z]{2,6}$/;
        return ipv4Pattern.test(ip) || domainPattern.test(ip);
    }

    document.querySelector("form").addEventListener("submit", function(event) {
        event.preventDefault();
        var ip = document.querySelector("#ip").value;

        if (!isValidIPorDomain(ip)) {
            alert("Please enter a valid IPv4 address or domain.");
            return;
        }

        socket.emit("start_scan", { ip: ip });
        document.querySelector("#status").innerText = "Scanning ports...";
        document.querySelector("#results tbody").innerHTML = "";
        document.querySelector("#target-ip").innerText = "Target IP: " + ip;  // 검색 중인 IP 업데이트
        openPorts = [];
        scanResults = [];
        document.querySelector("#open-ports").innerText = "";
    });

    socket.on("scan_update", function(data) {
        if (data.port !== undefined && data.status !== undefined && data.service !== undefined && data.banner !== undefined && data.error_message !== undefined) {
            scanResults.push(data);
            var row = document.createElement("tr");
            row.innerHTML = "<td>" + data.port + "</td><td>" + data.status + "</td><td>" + data.service + "</td><td>" + data.banner + "</td><td>" + data.error_message + "</td>";
            document.querySelector("#results tbody").appendChild(row);

            if (data.status === "open") {
                openPorts.push(data.port);
                document.querySelector("#open-ports").innerText = "Open ports: " + openPorts.join(", ");
            }
        }
    });

    socket.on("scan_complete", function(data) {
        document.querySelector("#status").innerText = "Scan complete in " + data.duration + " seconds";
        document.querySelector("#download-buttons").style.display = "block";
    });

    socket.on("scan_error", function(data) {
        alert(data.error);
        document.querySelector("#status").innerText = "Scan error";
    });

    document.querySelector("#download-pdf").addEventListener("click", function() {
        var resultsStr = JSON.stringify(scanResults);
        window.location.href = "/download/pdf?results=" + encodeURIComponent(resultsStr);
    });

    document.querySelector("#download-json").addEventListener("click", function() {
        var resultsStr = JSON.stringify(scanResults);
        window.location.href = "/download/json?results=" + encodeURIComponent(resultsStr);
    });
});
