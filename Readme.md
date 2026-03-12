# Secure Cloud Authentication System

## Overview

This project implements a secure cloud authentication service designed to demonstrate automated threat detection, mitigation, and resilience under attack conditions. The system integrates multiple defensive layers including authentication controls, role-based authorization, rate limiting, Web Application Firewall (WAF) protection, IP blocking, and centralized security event logging.

The primary objective of the system is to detect malicious behavior, automatically mitigate threats, and maintain service availability during attack scenarios such as brute-force login attempts, malicious payload injection, and high-frequency request floods.

The implementation is written in Go using the Fiber web framework and integrates Redis and MongoDB for threat detection and monitoring.

---

## Key Features

### Authentication and Authorization

* Secure user registration and login system
* Password hashing and verification
* JSON Web Token (JWT) based authentication
* Role-Based Access Control (RBAC) for protected endpoints

### Threat Detection

* Detection of repeated failed login attempts
* Monitoring of suspicious IP behavior
* Automatic tracking of authentication anomalies

### Automated Mitigation

* Automatic account locking after repeated failed login attempts
* Automatic IP blocking for suspicious activity
* Rate limiting to mitigate request flooding
* Web Application Firewall protection against malicious payloads

### Security Monitoring

* Persistent security event logging
* Security events stored in MongoDB
* Real-time monitoring of authentication and request activity

### Web Application Firewall (WAF)

The WAF middleware inspects incoming requests for suspicious payload patterns such as:

* Cross-Site Scripting (XSS)
* Injection attempts
* Malformed input payloads

Requests identified as malicious are blocked before reaching application logic.

### Rate Limiting

A rate limiting middleware protects the system from excessive traffic. Requests exceeding configured thresholds receive HTTP 429 responses.

---

## System Architecture

The application follows a layered security architecture where each layer validates the request before it reaches core application logic.

```
Client Request
      │
      ▼
Web Application Firewall (WAF)
      │
      ▼
IP Blocking Middleware
      │
      ▼
Rate Limiting Middleware
      │
      ▼
Authentication Logic
      │
      ▼
Threat Detection Engine (Redis)
      │
      ▼
Security Event Logging (MongoDB)
```

This layered design allows early detection and mitigation of malicious requests.

---

## Technologies Used

* Go
* Fiber Web Framework
* MongoDB
* Redis
* JWT Authentication
* TLS / HTTPS

---

## Project Structure

```
.
├── main.go
├── controllers
│   └── UserController.go
├── middleware
│   ├── RBACMiddleware.go
│   ├── ipblock.go
│   └── webAppFirewall.go
├── monitoring
│   └── security_logger.go
├── security
│   └── threat_engine.go
├── models
│   └── user.go
├── utils
│   ├── utils.go
│   ├── logger.go
│   └── jwt.go
├── cert.pem
├── key.pem
└── screenshots
```

---

## Installation

### Prerequisites

* Go
* MongoDB
* Redis

### Clone the Repository

```
git clone <repository_url>
cd cloud-security-system
```

### Install Dependencies

```
go mod tidy
```

### Start Redis

```
redis-server
```

### Ensure MongoDB is Running

The system requires MongoDB to store users and security events.

---

## Running the Server

Start the server using:

```
go run main.go
```

The application runs securely using TLS at:

```
https://localhost:3000
```

---

## API Endpoints

### User Signup

```
POST /signup
```

Example request:

```
{
  "username": "user1",
  "password": "password123"
}
```

---

### User Login

```
POST /login
```

Returns a JWT token upon successful authentication.

---

### Update User Role

```
POST /updateRole
```

Requires administrator privileges.

---

### Retrieve Security Events

```
GET /security/events
```

Access restricted to users with the `admin` role.

---

### Health Check

```
GET /health
```

Used to verify system availability during resilience testing.

---

## Security Event Logging

Security events are stored in MongoDB in the following structure:

```
{
  Type: "LOGIN_FAILED",
  User: "user1",
  IP: "127.0.0.1",
  Timestamp: "2026-03-12T21:28:42Z"
}
```

Event types include:

* LOGIN_SUCCESS
* LOGIN_FAILED
* ACCOUNT_LOCKED
* IP_BLOCKED
* WAF_TRIGGERED

These logs provide an audit trail of system activity and detected threats.

---

## Attack Simulations

### Brute Force Login Attack

Multiple incorrect login attempts trigger the threat engine.

Mitigation:

* Account locking after repeated failures
* HTTP 403 responses returned for subsequent login attempts

---

### Rate Limiting Test

High-frequency requests are sent to the `/health` endpoint.

Mitigation:

* Excess requests receive HTTP 429 responses

---

### WAF Injection Test

Example malicious payload:

```
<script>alert(1)</script>
```

Mitigation:

* Request blocked with HTTP 403 before authentication logic executes

---

### Suspicious IP Detection

Repeated malicious activity triggers automatic IP blocking by the threat engine.

---

## Resilience Evaluation Metrics

### Brute Force Login Attack

Detection Time: approximately 2 seconds
Mitigation Time: immediate (less than 1 second)
System Availability: 100 percent

### Rate Limiting / DoS Simulation

Detection Time: less than 1 second
Mitigation Time: immediate (HTTP 429 responses)
System Availability: 100 percent

### Web Application Firewall Attack

Detection Time: immediate
Mitigation Time: immediate
System Availability: 100 percent

### Suspicious IP Blocking

Detection Time: less than 1 second
Mitigation Time: immediate
System Availability: 100 percent

---

## Conclusion

The Secure Cloud Authentication System demonstrates a layered defensive architecture capable of detecting and mitigating common web-based attacks. Automated threat detection mechanisms such as rate limiting, account locking, IP blocking, and Web Application Firewall filtering allow the system to respond quickly to malicious activity while maintaining full service availability.

The system successfully meets resilience and recovery requirements by detecting attacks within seconds, applying mitigation immediately, and maintaining operational availability during attack scenarios.
