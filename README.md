# Incident-Response-Template
- Incident Response Steps

## Responding to a Security Event: A Detailed Guide
This document outlines the steps a Security Operations Center (SOC) Analyst should take to investigate and remediate a potential security threat on a company's computer system. The document references a general security architecture that includes Zscaler for web traffic monitoring, Palo Alto for firewall, Crowdstrike for device monitoring, Splunk for log aggregation, and Any.Run for sandbox analysis.

## Steps
**1. Isolating the Compromised Device:**

- Upon notification of a potential threat, the primary objective is to isolate the compromised device to prevent further lateral movement within the network.
- Access the Crowdstrike console and locate the device requiring investigation.
- Obtain the device's hostname, IP address, and other relevant information for tracking purposes.
  
**2. Endpoint Security Check:**

- Investigate the device's endpoint security solution (e.g., Crowdstrike) to identify any detections related to the incident.
- Navigate to the "Endpoint Security" section and locate the "Detections" tab.
- Analyze the listed detections for suspicious activity on the device.

**3. Web Traffic Analysis:**

- Access Splunk, a log aggregation tool, to examine the user's web traffic data.
- Construct a search query to filter the user's web traffic logs.
- Refine the search by excluding irrelevant data such as Javascript objects and URLs that don't contain suspicious keywords or phrases associated with the potential threat.
- Analyze the refined search results to identify any malicious websites visited by the user.

**4. Sandbox Analysis:**

- To gain a deeper understanding of the potential threat, utilize a sandbox environment to analyze the user's browsing activity.
- This document references Any.Run as a potential sandbox tool.
- Within the sandbox environment, observe the user's interaction with identified malicious websites.
- Take note of any connections made by the website and identify Indicators of Compromise (IOCs) such as malicious URLs, IP addresses, or file hashes.

**5. Firewall Log Analysis:**

- Investigate the firewall logs (e.g., Palo Alto) to identify any outbound traffic originating from the compromised device that might be suspicious.
- Look for unusual data exfiltration attempts or connections to unauthorized servers.

**6. Windows Event Log Analysis:**

- Analyze the Windows Event Logs on the compromised device to identify any signs of account compromise.
- Search for events related to user logins, credential changes, or suspicious processes.
- This information can help determine if the user's account was compromised by unauthorized actors.

**7. Investigation Conclusion and Remediation:**

- After analyzing the collected data, arrive at a conclusion regarding the nature and severity of the security event.
- In the scenario presented in the reference video, the investigation might determine that the user clicked on a malicious website that triggered spam and scam notifications, rather than a full-fledged virus download or data exfiltration attempt.
- Based on the conclusions, take necessary remediation steps. This might involve blocking access to malicious websites, resetting user credentials, or implementing additional security measures on the device.

**8. Documentation:**

- It is crucial to document the entire investigation process thoroughly.
- The documentation should include details such as the date and time of the incident, the affected device information, the investigation steps taken, the findings of the investigation, and the implemented remediation measures.
- Maintaining a detailed record of security incidents is essential for future reference and improvement of the organization's security posture.

