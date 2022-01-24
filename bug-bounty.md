No technology is perfect, and Ripio believes that working with skilled security researchers across the globe is crucial in identifying weaknesses in any technology. If you believe you've found a security issue in our product or service, we encourage you to notify us. We welcome working with you to resolve the issue promptly, as long as it falls in scope and is not one of the types of vulnerability listed as out of scope below.

# Program Rules
* Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.
* Submit one vulnerability per report, unless you need to chain vulnerabilities to provide impact.
* When duplicates occur, we only award the first report that was received (provided that it can be fully reproduced).
* Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.
* Social engineering (e.g. phishing, vishing, smishing) is prohibited.
* Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service. Only interact with accounts you own or with explicit permission of the account holder.

# Disclosure Policy
* Let us know as soon as possible upon discovery of a potential security issue, and we'll make every effort to quickly resolve the issue.
* Provide us a reasonable amount of time to resolve the issue before any disclosure to the public or a third-party.

# Rewards
Ripio may provide rewards to eligible reporters of qualifying vulnerabilities. Our minimum reward is $100 USD. The bounty table for this program outlines the usual minimum rewards based on the assessed CVSS score for in-scope properties (see section on Scope). We reserve the right to reward vulnerabilities based on impact. Clarity and high technical skills in your report can give you an extra reward.

# Qualifying Vulnerabilities
Examples of vulnerabilities Ripio is interested in receiving:

* Authentication flaws
* Cross-site scripting (Stored, Reflected, DOM)
* Any type of Injection (SQL, NOSQL, LDAP, NOSQL, OS, XML, Eval)
* Cross-site request forgery on sensitive controllers (CSRF/XSRF)
* Mixed content scripts (scripts loaded over HTTP on an HTTPS page)
* Server side code execution (Ej. Exposed consoles or server-side template injection)
* Privilege Escalation (lateral and vertical)
* Business logic abuse with clear impact.
* IDOR (Insecure Direct Object Reference)
* XML External Entity injection
* Security misconfigurations with clear impact.
* Server Side Request Forgery.
* Remote File Inclusion.
* Unvalidated Redirects and Forwards


# Restrictions
* Massive automatic scanning is not allowed. Please do creative testing.
* If you significantly degrade our service, you risk a program ban.
* No DoS - Our cloud providers prohibit this activity.
* Participation in this program is prohibited for internal employees-

# Non-Qualifying Vulnerabilities
When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) security impact of the bug. The following issues are considered out of scope:
* Clickjacking on pages with no sensitive actions.
* Comma Separated Values (CSV) injection without demonstrating a vulnerability.
* Missing best practices in SSL/TLS configuration.
* Any activity that could lead to the disruption of our service (DoS).
* Spamming.
* Any physical attempts against Ripio property or data centers.
* Use of out-of-date 3rd party libraries without proof of exploitability.
* Vulnerabilities in 3rd party scripts used on Ripio's websites.
* Vulnerabilities which involve privileged access to a victim's device(s).
* Reports that affect only outdated user agents or app versions -- we only consider exploits in the latest browser versions for Safari, FireFox, Chrome, Edge, IE and the versions of our application that are currently in the app stores.
* Unauthenticated/logout CSRF.
* Cross-Origin Resource Sharing (CORS).
* User existence/enumeration vulnerabilities.
* Password complexity requirements.
* Reports from automated tools or scans (without accompanying demonstration of exploitability).
* Social engineering attacks against Ripio employees or contractors.
* Content spoofing and text injection issues without showing an attack vector/without being able to modify HTML/CSS.
* Non-sensitive (ie. non-session) cookies missing the Secure or HttpOnly flags.
* Enforcement policies for brute force or account lockout.
* Descriptive error messages or headers (e.g. Stack Traces, application or server errors, banner grabbing).
* Lack of rate limiting on a particular API or other 'load testing' types of issues.
* Missing security headers without additional details or a POC demonstrating a specific exploit.
* SPF, DKIM, DMARC or other email configuration related issues.
* HTTP 404 codes/pages or other HTTP non-200 codes/pages.
* Disclosure of known public files or directories, (e.g. robots.txt,readme.html on WordPress, etc).
* Self-XSS and issues exploitable only through Self-XSS.
* Obfuscated Code on native apps.
* Exported components with no real security impact on native apps.
* Issues related to credentials/info disclosure in public sources such as Trello, GitHub, Wayback, etc, will be analyzed in each case and may not be eligible for bounty.

# Safe Harbor
Any activities conducted in a manner consistent with this policy will be considered authorized conduct and we will not initiate legal action against you. If legal action is initiated by a third party against you in connection with activities conducted under this policy, we will take steps to make it known that your actions were conducted in compliance with this policy.

Thank you for helping keep Ripio and our users safe!
