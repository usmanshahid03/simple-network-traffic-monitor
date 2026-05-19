
Overview
A C++ based network security monitoring system that analyzes network traffic and detects connections to suspicious or blacklisted websites. The system flags any source IP addresses that attempt to access known malicious URLs.
Features

Monitors multiple network traffic entries simultaneously
Maintains a blacklist of suspicious websites
Detects and reports suspicious connections with source IP and destination URL
Simple and lightweight with no external dependencies

Project Structure

nettraf class — Represents a network traffic entry containing a source IP address and a destination URL
secsys class — The core security system that holds the suspicious website blacklist and monitors traffic against it

How It Works

A list of suspicious websites is defined
Network traffic entries (IP + URL pairs) are created
The security system scans each traffic entry
If a destination URL matches any blacklisted site, an alert is printed to the console

Requirements

C++ compiler (g++ recommended)
No external libraries or config files required
