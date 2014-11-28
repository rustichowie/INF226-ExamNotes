Exam Notes INF226
=================

##Chapter 1:

Software is a part of our everyday life.
We depend on it.
It needs to be available at all times.

###1.1
CERT was created as a response to the "Morris worm" in 1988.
CERT started cataloging vulnerabilities up until 2008.

####1.1.1
We need to think about flaws in critical systems like cars, airplanes, banks etc..
"Nokia 1100" Insident.
Charlie Miller presented in 2009 that he could take control over a Iphone remotly by sending several messages to it.
The kind of attack he used allows him to execute malicious code without the victim having to do anything.

####1.1.2
Cars use software for many parts of there system.
Toyota has had to recall millions of priuses because of software clitches.
Software problems in radiation therapy devices causes 28 patients to receive excessive amounts of radiation. Several died.

###1.2
Security has never been a core part of the software development cycle, only added as you go.
Schooles and Colleges doesnt have a great focus on security, but this is getting better.
Problems arrise if novice programmers with little training in security starts creating critical systems (financial, medical, etc.)

###1.3
Software flaws are costly! 

###1.4
Experts define Information security as the ability to protect: confidentiality, integrity, and availability of the information.
Confidentiality: Information is not accessed by unauthorized users. (Also includes keylogging and other forms of evesdropping).
- Typical measures: encrypting data at rest(files, db) and in transit (SSL, SSH)
Integriry: Information is not modified without proper authorization.
- Typical measures: Hashing and digital signatures
Availabiltiy: Information is made available to authorized users when they need it.

We can help ensure resilience by integrating security in the software development cycle.


##2. Characteristics of Secure and Resilient Software

Comparing functional and non-functional requirements.
Look at earliest phases of software development to find and document essential qualities of security and resiliency.

###2.1 Functional Vs Nonfunctional Requirements
What software is expected to do is describes as functional requirements.
These show up early as customers/users of the software describe what they want.
Nonfunctional Requirements(NFR) are the quiaity, security and resilience aspects.

Developers don't state how secure there software is, or market it that way.
You put a big bulls eye on yourself if you do so (Oracle database insedent)

Institute of Electronics and Electrical Engineering(IEEE) defenition of requirements:

Functional: Specifies a function that a system must be capable of performing.
NFR: Describes how the system will perform the functional requirements.

Resilience tests verify that functions designed meet NFR and operates as expected.
Also validates that implementation of those functions is not flawed or haphazard.

###2.3 Families of NFR

Resilient software demonstrate several characteristics that helps every stakeholder in a software prosject.
See page. 17 for list.

###2.4 Availability
Address the specific needs of the users who access the system.
To determine availability ask the following questions:
- What are your scheduled operations? 
- What times of the day and what days of the week do you expect to be using the system?
- Helps determine when the system MUST be available.
- Set up  normal operation hours when the system must be available.
- How often can you tolerate outage during these times?
- Goal here is to understand the impact on the users.
- Tells you if there is possible to have scheduled outage during these times.
- How long can an outage last?
- Tells you how long a user is willing to wait.

Depending on the answers to these quiestions you should be able to identify the level of availability required.
- High - Available during specific hours with no unplanned outages.
- Continuous operations - available 24/7 with no scheduled outage.
- Continouos availabilty - available 24/7 with no planned or unplanned outage.


###2.5 Capacity
The need for support personel to configure the system as the environment changes.
You need a external separate config file.
Programmers should not have to be called in to do these configs. 
Support personel should be able to change config and restart system.
Made simpler when runtime environement can be changed on the fly. (To accomendate change in user traffic, hardware..)

###2.6 Efficiency
Degree that a system uses computational resources, such as CPU cycles, memory, disk space, buffers and communicational channels.
Can be caracterized using these dimentions:
- Capacity - Max number of users, transactions etc..
- Degradation of service - Effect of a system with cap X when system receives X + 1 transations.

NFR should describe what to do when limitations are reached.

###2.7 Interoperability
Abiltiy to work with other systems without any special efforts.
You should use common standards to make this happen. 
For communication (TCP/IP)
Encryption (SSL, TLS)
Databases (SQL)
Data structures or definitions (XML , JSON)
Interfaces between common software functions (API)

Also conserned with use of internal standards and tools for development.
When possible reuse existing components when creating new software.

###2.8 Manageability
Focused on easing the ability for support personnel to manage application.
Allows support to move application around to different hardware installations or run on virtual machines.
So never tie your application down to a single hardware or OS.
Build software as highly cohesive and loosed coupled as possible.

###2.9 Cohesion
Increased as the responsibilities(methods) of a software module have many common aspects and are focused on a single subject.
Low cohesion can lead to following:
- Increased difficulty in understanding module
- Increaded difficulty in maintaining it. (because logical changes may affect multiple modules)
- Increaded difficulty in reusability

###2.10 Coupling
Use interfaces instead of directly pointing to concrete class.
Loose coupling provides extensiabilty and manageability.
Can easily add new concrete classes which uses the same interface.

###2.11 Maintainability
Refers to modification of software after release. (correcting flaws, improve quiality etc)
Expensive and time consuming
Hard with little to no documentation
Yes to these quistions determine maintainability:

* Can I find related code?
* Can I understand it?
* Is it easy to change?
* Can I easily verify changes?
* Can I make changes with low risk of breaking something else?
* If I break something, is it easy to fix?

Not enough to require that the application needs to be maintainable, be more spesific.

###2.12 Performance
Addresses three areas:

* Response time
* Volume of simultanious transaction
* Number of simultaneous users

###2.13 Portability
Software considered portable if cost is less than the cost of rewriting from scratch.
Adapting software to be able to execute it on changing environments.
Most possible if when there is a generelized abstraction between application logic and all system interfaces.

###2.14 Privacy
Related to security, but also includes nonsecurity aspects of data collection and use.
Don't collect everything available, could be come a privacy concern.
Misuse and overcollection should be controlled by requirements.
U.S Federal Trade Commission on fair information practice prinsiples:

* Notice/Awareness
	* Website should tell user how it collects and handles user information.
	* Privacy policy should clearly specify what data it collects.
* Choice/Consent
	* Websites must give control over how personally identifying info is used.
	* Primary problem here is collecting info for one purpose but using it for something else.
* Access/Participation
	* Users should be able to review, correct, delete personal information.
* Integrity/Security
	* Site must implement policies, procedures that prevent unauthorized access to personel info.
	* Example: Loss of financial info.

###2.15 Recoverability
Related to relieability and availability.
How quickly can a system recover after unexpected outage or system failure.
Table 2.1 page 26 shows levels of software criticality and recovery methods.

###2.16 Reliability
Entire field of study!
Generally refers to systems ability to continue operations after hostile or accidental impacts to dependent systems.
Can be very critical in case of aircraft life support etc..
Defined in several ways:

* Capacity of a device to perform as intended
* Resistance to failure
* Ability to perform required function under stated conditions
* Aility of something to "fail well" (without catastrophic consecvence)

###2.17 Scalability
Ability to grow in its capacity to meet rising demand.
Scale in users, transactions per second, simultaneous db calls.

####2.18 Security

* Confidentiality
* Integrity
* Availability

Few security objectives for resilient software:

* Identify users
* Access or modification of data is logged
* Authorize access
* Detect attempted intrutions
* Ensure uncorrupted data
* Ensure confidential data are kept private
* Ensure that app can survive attacks or fail securely

###2.19 Serviceability/Supportability
Ability of support personnel to install, configure and monitor software.
Identify faults, perform root-cause analysis.

How to facilitate this:

* Help desk
* Network monitoring
* Event logging


##3 Security and Resilience in the Software Development Life Cycle
Examine in detail the environment in which software is developed and deployed while applying security principles.

###3.1 Resilience and Security Begin from Within
Only way to ensure secure/resilient software is to integrate that mindset throughout the entire software developement cycle.
The earlier the cheaper it becomes!
Much of this is common sense, therefor easy to implement in a development cycle.
See Figure 3.1 page 38

###3.2 Requirements Gathering and Analysis
Intended to map out NFR for the system
Important to have these ready before translating business requirements to technical requirements.
System designers and analysists should be very familier with the environment in which they are operating.
Should have knowledge about:

* Organizational security policies
* Privacy policies
* Requlatory requirements
* Other industry standards

NFRs are mapped against critical security goals:

* Confidentiality
* Integrity
* Availability
* Nonrepudiation
* Auditing

Finally these are prioritized and documented for the next phases in the dev cycle.

###3.3 System design and Detailed design
Threat modeling and design reviews.
Design reviews so that no bad design problems occur later in the process
Threat modeling is an excellent way to determine technical security posture of an application
4 Steps:

* Functional decomposition
* Categorizing threats
* Ranking threats
* Mitigation planning

####3.3.1 Functional Decomposition
Typically performed using data flow diagrams
Key aspect is to understand boundaries of untrusted and trusted components. (allows better understanding of attack surface)

####3.3.2 Categorizing Threats
**STRIDE**: Framework developed by Microsoft for classifiyng threats

* **S**poofing of user identity.
* **T**ampering with data not meant for you for malicious purposes.
* **R**epudiation: Ability of a system to trace actions performed by users.(Users deny performing an action they actually did)
* **I**nformation disclosure: Exposing of sensitive data.
* **D**enial of service(DoS)
* **E**levation of privilege.

####3.3.3 Ranking Threats
Require a fair amount of subjective judgement.
**DREAD** is a Microsoft developed model.
We arrive at a risk rating by asking the following quiestions:

* **D**amage potential?
* **R**eproducibility?
* **E**xploitability?
* **A**ffected users?
* **D**iscoverability?

####3.3.4 Mitigation Planning
You can map ranked threats to potential vulnerabilities in the system.

###3.4 Design Reviews
Ensures that the system is secure from the start.
Usally performed by a external security expert.
Uses diagrams and lists from previous phases as base.

###3.5 Coding Phase
Static analysis and peer review!

####3.5.1 Static analyis
Automated tool for discovering Bugs, style checks, type checks etc..

OPS! Can have a large percentage of false positives, but does catch many vulnerabilities that may plauge the application.

####3.5.2 Peer review 
Time consuming
Developers review each others code and provide feedback.

###3.6 Testing
Penetration testing and other forms of security testing.
Both manual and automated tools can be used.

###3.7 Deployment
CAB - Change advisory board.
Responsible for all changes in the production environment.

Ongoing monitoring and scheduled security tests!


##4 Proven Best Practices for Resilient Applications
Provides details on some critical concepts related to web security and breaks them down to 10 principles and practices.

###4.1 Critical concepts
Before we could rely on network architecture, firwalls and port restriction to secure applications. Income the Web!
Web traffic is never stopped, so it creates a hole in the architecture.

###4.2 The Security Perimeter
Simple definition: *The border between the assets we want to protect and the outside world*
Our first line of defense.

Inside our secure zone: Web server, App server, Db server.
Outside: Browser, external applications.

The security perimeter becomes blurry as the borders of a enterprise network blur.

###4.3 Attack Surface
Consept to identify, assess and mitigate risks to today's software systems.
Definition *All possible entry points that an attacker can use to attack the application*
Is the area of the application visible to the attacker (open sockets, RPC entry points, or humans them self)

In a web application the attack surface is defined by:

* All the accessible web pages
* Every point at which the attacker can interact with the app (cookies, url variables)
* Every function provided by the application.

####4.3.1 Mapping the Attack Surface
Techniques used in the case of Webapps:

* Crawl every page (Using automated tool)
* Identify all the available functionalities
	* Follow every link
	* Fill every form with valid/invalid data and submit
* Look for points where user supply input
	* GET requests with string params
	* Form generated POST requests
	* HTTP Headers
	* Cookies
	* Hidden params

###4.3.2 Side Channel Attacks
Attackers target implementation rather then the weakness directly.
Called side channel attacks

##4.5 Practice 1: Apply Defence in Depth
Emphazises that security increases when implemented as a series of overlapping layers of control.
They provide three elements needed to secure assets: prevention, detection and repsonse.
If one layer has a weakness, multiple others counter it.

Have several layers of protection. Both on a machine and human level.

##4.6 Practice 2: Use a Positive Security Model
Whitelisting!
You should reject by default.

##4.7 Practice 3: Fail Securely
Handle errors securely.
Especially important in security modules.
If methods handeling security fails, return false!

##4.8 Practice 4: Run with Least Privilege
User accounts have the least amount of privilege required.
Also known as Principle of least authority

##4.9 Practice 5: Avoid Security by Obscurity
Attempting the secure application based on the difficulty in finding or understanding the security mechanisms.
Relies on secrecy. It is a weak!
Any system that tries to keep its algorithms secret for security reasons is quickly dismissed by the community.

##4.10 Practice 6: Keep Security Simple
Avoid overly complex approaches.
Break security modules down into these discrete objectives:

* Keep services running and information away from attackers
* Allow the right users the right access.
* Defend every layers as if it is the last layer.
* Logging.
* Isolate resourses.

##4.11 Practice 7: Detect Intrusions
Require three elements:

* Capability to log security-relevant events
* Procedures that ensures monitoring of those logs
* Procedures to respond to a intrusion as it is detected

##4.12 Practice 8: Don't Trust Infrastructure
You never know exactly what environment you application runs on, therefore don't rely on it.

##4.13 Practice 9: Don't Trust Services
Any external system. 
You have no control over it, so make sure you are protected.

##4.14 Practice 10: Establish Secure Defaults
Every application delivered should be secure by default out of the box!
Leave it to users if they want a less secure model.
It means settings should be set to highest security from the start!

##4.15 Mapping Best Practices to NFR
See page 63 in the book.

##5 Designing Applications for Security and Resilience
Topics include designing applications to meet NFR.
Use and abuse cases.

###5.1 Design Phase Recommendations
Security often gets little priority if time or resources is an issue.
Project managers should plan and allow time to ensure security requirements are included in design work.

####5.1.1 Misuse Case Modeling
Not only use cases that needs modeling.
Needed to understand nd address security and resilience charecteristics of software.
User interaction analysis identifies scenarios the system isn't capable of handeling.
Use case scenarios is a good starting point for creating a threat model.
Use case modeling usefull for all parties involved(managers, customers, developers, testers)
It's all about understanding the different ways your system can be used/misused.
Tracability matrix = track misuse cases to functionality in software.

####5.1.3 Threat and Risk Modeling
**Threat Modeling**
Determining attack surfaces by examining applications trust boundaries, entry points, data flow and exit points.
Is based on the functionality of the application.
Iterative technique to identiy threats.
Starts by checking against NFRs.
Performed during design phase so that you have security controls etc in place from the start.
Get feedback from different resources(parties) and update model as you go.

**Risk Modeling**
Ranking threats as they are related to business objectives, compliance, regulatory requirments, and security exposure.
Many vulnerabilities isnt coding problems but design problems

####5.1.4 Risk Analysis and Modeling
Review security and privacy requirements.
Process is referred to as *risk analysis*

Inludes:

* Threats and vulnerabilities related to your project, internal and external.
* Evaluation of external writen code
* Include all legacy code if project is rerelease of old project.
* Detailed privacy analysis
	* What personal data is collected?
	* What notice/consent experiences are provided
	* What common controls between internal and external users?
	* How are unauthorized access prevented?

####5.1.5 Security Requirements and Test Case Generation
Rules of thumb when doing *Threat modeling*

* If the data does not cross trust boundary: don't care about it.
* If threat requires that attacker is allready running code on the client at your privilege level: don't care about it.
* If your code runs with elevated privilege: be conserned.
* If code invalidates assumptions made by other entities: be concerned.
* If code listens on the network: be concerned.
* If code retrieves data from internet: be concerned.
* If code uses data from file: be concerned.
* If code is marketed as safe/secure: be concerned.

###5.2 Design to Meet NFRs
Application should provide following:

* Assurance that users are identified and properly verified.
* Assure authorization of users
* Ability to detect unauthorized/unauthenticated intrusions.
* Assurance that malicious code do not effect people.
* Assurance that communication and data are not corrupted.
* Assurance of no repudiation.
* Confidential stuff is kept private
* Auditing options for security mechanisms
* Application can survive attacks

NFRs often cause design decision trade-off (High performance, availability or security)

###5.3 Design Patterns
The Secure Design Patterns report by SEI lists general solutions to security problems.

* *Architectural-level patterns:* Focus on high-level allocation of responsibilities among components, and define interactions between them.
	* Distrustful decomposition
	* Privilege separation
	* Defer to kernel
* *Design-level patterns:* How to design and implement elements of a high-level system component.
	* Secure factory
	* Secure strategy factory
	* Secure builder factory
	* Secure chain of responsibility
	* Secure state machine
	* Secure visitor
* *Implementation-level patterns:* Address low-level security issues.
	* Secure logger
	* Clear sensitive information
	* Secure directory
	* Pathname canonicalization
	* Input validation
	* Resource acquisition is initialization

###5.4 Architecting for the Web
Three tier architecture: Web server, App server, Db server.
We can separate conserns (loose coupling) and implement security in the places they do the most work.
Other advantages:

* Centralization can use mainframe-like environment that is scalable, predictable, and easily monitored.
* Reliability is enhanced since equipment resides in a controlled environment.
* Scalability since you can add servers or processors to increase performance
* Web browsers are awesome because even if OS or hardware changes they stay the same.

##6 Programming Best Practices
**SKIPPED OWASP TOP 10**

###6.3 OWASP Enterprise Security API (ESAPI)
Designed to take care of many aspects of application security automatically.
Helps developers guard against security related design and implementation flaws.
All Security Methods is mapped to OWASP TOP 10.

####6.3.1 Input Validation and Handeling
Improper input handeling is the most common weakness in applications today.
Leading cause of a lot of problems.
Every input from user needs validation.

Example problem: Netshop which stores price in hidden field at client side and uses that to calculate actual price...
Use of proxy browser tools.

Input handeling = validation, sanitization, filtering, encoding, and/or decoding of input data.
WHITELIST!

####6.3.2 Client-Side Versus Server-Side Validation
Beneficial for user experience to validate on client side, but you NEED Server-Side validation
Never do security on client side.

####6.3.3 Input Sanitization
Transforming input from original form to an acceptable form
Example: HTML tags.
Take care for semantically similar characters.

####6.3.4 Canonicalization
Deals with converting data with various possible representations into a standard representation acceptable by the application.
Most common is *path canonicalization* of files and URLs.
This is used to enforce access restrictions.
Application should specify acceptable characterset (UTF-8, ISO-8859-1..)
Also implement custom sanitization suited for the application.

####6.3.6 Approaches to Validating Input Data

**6.3.6.1 Exact Match**

* Data is validated against list of known values.
* Requires definition of all possible values that are considered valid input.
* Provides strongest level of protection.
* Often not feasable because of large number of possible good values are expected (Name, address).

**6.3.6.2 Known Good**

* Data validated against list of allowable characters
* Requires definition of all acceptable characters
* Regex

**6.3.6.3 Known Bad**

* Data validated against list of unacceptable characters
* Useful for preventing specific characters from being accepted
* Highly suseptible to evasion using various forms of character encoding
* Weakest method

####6.3.7 Handeling Bad Input
Once you detect bad input  you have 3 choices:

* *Escpaing input:* Attempt to fix data by encoding it in a safe format
* *Rejecting input:* Dicard it
* *Do nothing:* Not recommended

####6.3.8 ESAPI interfaces
Parts of ESAPI which covers input handeling:

* Validator
* Encoder
* HTTPUtilities

###6.4 Cross-Site Scripting
Attacker try to inject client-side script on the browser of another user.
If an attacker gets the users browser to execute there script it is within the security context of the application. 
Using the level of privilege that user has. It can read, modify or transmit the users data.
Can have there session hijacked.

####6.4.1 Same Origin Policy
The cornerstone browser security.
Permits scripts running on pages originating from the same site to access each other's methods and properties, but prevents access to most methods and properties across pages on different domains. Consists of three things:

* Domain
* Port
* Protocol

Does not protect agains everything, only applies to:

* Scripts acess across browser windows and frames
* Script access to contents of an iframe or parent frame
* Connection using XMLHttpRequest objects
* Loading images and scripts using <tag src= >
* Loading style sheets

####6.4.2 Attacks through XSS

Three types:

* Persistent
* Nonpersistent
* DOM-based

2 and 3 require user to either visit crafted link or visit a malicous Web page containing a form which when posted to the vulnerable site launches the attack.
Malicious forms often takes the place of the real form. ( Can be sent automatically using JS).

Persistent attacks occur when the malicious code is submitted to the website where it is stored over time.

**6.4.2.1 Persistent Attacks**

If a user submits a script to a forum or message board, every user which loads the page it is posted to will be exposed.
In worst case it can hijack the session id from your cookies.

**6.4.2.2 Nonpersistent Attacks**

If you use a url variable to show something on you page, such as username the url can be maipulated to store a script.

**6.4.2.2 DOM-Based Attacks**
If you have JS which embed the URL as part of the page. Example as a form action.
If you place scrips directly into the url it will be executed on the client.

####6.4.3 Prevention of XSS
One or more of these techniques are used:

* Encode fields to escape HTML in output
* Content-Type: text/html; charset[encoding]
* Input validation
	* Never trust input
	* Avoid using input variables within client-side scripting code.
* Cookie security
	* HttpOnly
	* Secure

####6.4.4 ESAPI Interfaces
* Encoder
* Validater

###6.5 Injection Attacks
Many types of injection: SQL, LDAP, XML, etc..

####6.5.1 SQL Injection
Attacker exploit improper validation of input used in an SQL Query.
Very dangerous!

####6.5.4 Defending Against SQL Injection
Validate input.
Use PreparedStatements (Separates Data and Code of the Query)
Remove dedault user accounts.
Disable unnecessary functionality within db server.
Db accounts should have minimal access needed.

###6.6 Authenication and Session Management
Something you know - Password
Something you have - Security token or smartphone
Something you are - Fingerprint

If you handle sensistive data you should use a combiniation of at least 2.
Attackers attempt to take control over someones identity.

####6.6.1 Attacking Log-in Functionality
Typical attacks:

* *Username enumeration:* allows attacker to enumerate valid usernames to use with further attacks
* *Password guessing:* most successful when users are allowed to use weak passwords
* *Brute-force attack:* Succeeds if you have no account lock-out or max nr of login attempts.
* *Authenticatipn mechanism attack:* Most effective with weak authentication (HTTP Basic Authentication)

Defenses against:

* Generic failed login message (Dont give information away)
* Enforce lock-out after x number of attempts (Should trigger an alert sent to approperiate personnel)
* Server-side enforcement of strong passwords.

####6.6.2 Attacking Password Resets
Typical attacks:

* Requires user ID to initiate reset, this allows for username enumiration
* Using bad security questions (fav color?)
* Unlimited number of answers to security question
* Displaying password directly to the user upon reset
* Allowing users to define own sec questions.
* Using standard or weak passwords as new password

Defenses against:

* manual pssword reset (if needed)
* Consider multiple sec questions
* Dont generate password for them, instead send reset url to email.

###6.7 CSRF
Used for:

* Attacking trust a applciation has with its users
* Abusing shared cookies to send requests to apps he/she is authenticated

Attacker relies on:

* User being logged in
* Has persistent authentication(cookie) but not csrf token in the forms.

###6.8 Session Management
Stored sessions are vulnerable for hijacking.

####6.8.1 Attacking Log-Out Functionality
Typical attacks:

* Applications which doesnt let users log out
* Logout button doesnt terminate the session correctly

Defenses against Log-Out attacks:

* Give users logout option
* Users are educated on importance of logging out
* Automatic expiring user session
* Clear session ID cookie
* Set cookies as nonpersistent

Defenses Against Cookie Attacks:

* Never store sensitive information
* Only ID for users session, which is used to look up on a session table at server-side
* secure flag
* httponly flag

###6.9 Access Control
Authorization should never rely on obscurity.
Authorize every page, not only those directly referenced in the webpage.

Defenses:

* Implement role-based access control
* Issue allow privileges on a case-bycase basis, and deny by default
* Log all failed access requests and review these

###6.10 Cryptography
Includes:

* Hashing functions
* Public key infrastructure
* Data integrity
* Authentication

####6.10.1 Hashing and Password Security
Hash is used to verify integrity of data.
HASHING IS NOT ENCRYPTION. Dont use it for confidentiality
Most common usage is storing a representation of passwords.

####6.10.2 Attacking the Hash

Dictionary attacks:

* Calculate hashes for a list of common words
* Compare those with db table
* if match, uses that word in clear text as password

Brute-force Attack:

* Try every possibility
* Takes long and is not feasible if strong password requirement is enforced

Precomputed Attacks (Rainbow tables)

* You precompute the hashes and store them as a mapping table.
* During attack you only compare (much faster)
* Solution to this: Salted Hashes
	* A salt is a random value appended to a password before it is hashed
	* salt is not secret and are stored along with the password hash.
	* Idea is to force recalculation of the hash on every attempt.

####6.10.4 Message Authenication Code (MAC)
* Hashes can be used to create unique fingerprint to detect if the message was changed.
* IDEA:
	* calculate hash before sending
	* calculate hash after and compare
* Problem is: If you send hash with the message the attacker can recalculate it and replace it with the new hash
* Solution: HMAC
	* calc the hash using a secret key or password
	* attacker dont have secret so he cant change anything without us knowing

###6.13 Additional Best Practices for Software Resilience

####6.13.1 Externalize Variables
To help meet NFRs like supportability, maintainability, manageability and reliability it is good pratice to store configuration variables external from compiled code, likely in a config or properties file on the server.
Consider encrypting it if it stores sensitive data.

ESAPI - EncryptedProperties can be used for this.

#####6.13.3 Initialize Variables Properly
int i = 3; NOT int i;

####6.13.4 Do Not Ignore Values Returned by Functions
if method returns value; Store it!

####6.13.5 Avoid Integer Overflows
BE mindful of maximum int values.

###6.14 Top 10 Secure Coding Practices

Recap:

1. *Validate input:* ALWAYS validate input from all sources. 
2. *Heed compiler warnings:* Compile code using highest compiler alert level
3. *Architect and design for policy enforcement:* Design and implement softwae that enforces security and corporate policies.
4. *Keep it simple:* Dont make things uneccesarry complex
5. *Default deny:* WHITELIST
6. *Adhere to the principle of least privilege:* Least set of privileges neccasary
7. *Sanitize data sent to other systems:* input between different sub components might be targeted, sanitize the data.
8. *Practice defense in depth:* Have many layers of security. Secure coding and secure environment together
9. *Use effective assurance techniques:* Pen testing, fuzz tsting, source code audits are good practices.
10. *Adopt a secure coding standard:* Develop and/or apply a secure coding standard for your target language/platform



##7 Special Considirations for Embedded Systems, Cloud Computing, and Mobile Computing Devices
Look at special systems and environments. Including security challenges.

###7.1 Embedded Systems
Special-purpose devices.
Need new NFRs that are not assiciated with Web users or other general cases.
Few ways of updating embedded systems like DVD players, remotes, other systems.

####7.1.1 Bad Assumptions About Embedded Programming
Bad assumptions are to blame more than the exploitability of the software.

1. Devs think embedded systems are inherently more secure.
	* Source code may not be available
2. Users assume that embedded systems are more secure.
	* In the event of unexpected behaviour, most developers blame the users. but the developers neven explained to the user any assumptions related to the device.
3. Making incorrect assumptions about security posture requirements of the user.
	* Developers think that a system is secure if it costs more to hack into it then what you are protecting is worth.

####7.1.2 New Mantras
Security is not all about encryption. Policy, procedure and implementation also important.
Secure code is not alone a secure system.

####7.1.3 The Framework
Basic framework for considering security of your device:

1. *Environment:* Deternime assumptions, threats and required policies for your target environment.
2. *Objectives:* Determine security objectives. Consider data or operations it will protect which threats require counter measures.
3. *Requirements:* Determine your functional security requirements.

Condensed form of the Common Criteria (Chapter 9).

###7.2 Distributed Applications/Cloud Computing
Predictions for the future is attacks against cloud services and use them to direct and control attacks throughout the network.
Easy to patch and update Cloud applications as you have constant contact with them.
Unique set of security problems, but also a lack of standardization.

Microsoft is proposing what is called: Cloud Computing Advancement Act to force change in three main areas of internet policy:
privacy, security and the international legal framework.

The Gartner Group identified seven key security risks in cloud apps:

1. *Privileged user access:* If you have sensitive data processed outside your enterprise (in the cloud), you have no control over it. Get as much info about the cloud provider as you can about how your data is handled.
2. *Regulatory compliance:* Customers are in the end responsible for there own data (even when stored at a provider). Therefor service providers should undergo security inspections and audits to be trusted.
3. *Data location:* You never know how or where your data is stored in the cloud. Ask providers if they follow local regulations when storing or if they commit to a single juristiction.
4. *Data segregation:* Find out how the provider seperates your data with someone elses.
5. *Recovery:* You should receive info in what happens with your data incase of a disaster. Will it be recovered and how long will it take?
6. *Investigative support:* Investigating illigal activity in the cloud may be imposible. Unless the provider garenties logging and tracking of these kinds of actions you should assume it is impossible.
7. *Long-term viability:* Make sure your data remain available if your provider becomes broke or bought by a bigger company.

Most important abstraction of distributed systems: Remote Procedure call (RPC) model.
Inspired EJB, Java RMI, XML-RPC, SOAP etc...
New Model: Representational State Transfer(REST).

####7.2.1 REST
REST is a generic concept, and often applied to define APIs over HTTP/HTTPS.

REST contraints:

* *Uniform interface:* All resources present the same interface to clients; Mapping between resource and URI
* *Statelessness:* Server keeps no state; all requests must carry session-oriented information.
* *Caching:* Clients and Proxies can cache responses marked as Cachable.

####7.2.2 REST Stateless Authentication
Authentication is neccessary in every request. 
No concept of session maintained on the server side.
Applications must implement strong authentication protocols and prevent attacker from capturing key or password.
Similar to HTTP Basic Authentication.

####7.2.3 Attacking Distributed APIs
You need to validate all data received from outside the security perimiter.
REST is susceptible to the risks of request replay.

####7.2.4 Securing Distributed APIs
* Strong as possible validation
* Enforce authentication/authorization on every request
* Use HTTPS
* Use HMAC for authentication scheme. It prevents replay attacks and authentication token reuse.
* Never use Basic Authentication

###7.3 Mobile Applications
Threat landscape quite different from web.
Be careful when storing/caching locally on the phone.

##8 Security Testing of Custom Software Applications
Topics include:

* The true cost of waiting to find and removing software flaws.
* Manual and automatic source code review techniques
* Implementing code analysis tolls
* Penertration testing
* Black box testing
* Quility assurance testing

###8.1 Fixing Early Vs Fixing After Release
Removing a flaw/vulnerability in design/implmenetation phase costs 30-60 % less than in production.

There are direct and indirect costs.
Indirect is not easily measured (Company reputation), but direct cost:
`Average cost to code a fix = (number of developers man-days * cost per man-day) / number of defects fixed`

Additional costs:

* System test costs
* Implementation costs
* System costs
* Postproduction costs

Secure testing ensures no defects in implementing your secure design (design created with threat modeling etc..)

###8.2 Testing Phases

* Unit Testing 
* Integration Testing
* Quality assurance Testing
* User acceptance testing


###8.3 Unit Testing
Best practice for overall good code quality, but has some security advantages.
Helps prevent defects from finding their way into larger testing phases.
Important to document what you test.
What can developers discover with unit testing?

* Boundary conditions
	* Integer overflow
	* Path length (URL, file)
	* Buffer Overflow

Can also use *fuzzing* techniques.
Sending random data to interfaces. (100 000++)
One of the cheapest, and most effective way of identifying bugs.

###8.4 Manual Source Code Review
Scope limited to finding code-level problems.

Not used to reveal:

* Problems related to bussiness requirements that cannot be implemented securely
* Issues with the selection of a particular technology for the application
* Design issues that might result in vulnerabilities

Often called *white box* analysis. Because reviewers have full knowledge of the internal system and it's design.

###8.5 The Code Review Process
**First step:** Understanding the code and its purpose.
You cant review every line so finding the critical components is important.
**Second step:** Begin reviewing the identified components based on priority. Can be done by external teams.
Both developers and security experts should have a chance to see the components.
**Thrid step:** Coordinate with the code owners and help them implement fixes.
**Final step:** Study lessons learned during the process and identify areas for improvement.

Some common critical components:

* Authentication & Authorization
* Data protection routines
* Code that receives and handles data outside the trust boundary
* Data validation
* Error handeling
* Usage of OS and network resources
* Low-level infrastructure
* Embedded software components
* Isage of outdated APIs

###8.6 Automatic Source Code Analysis
It takes a lot of resources to do manual code review, bigger bussineses uses automatic tools instead.
Can be very helpful as they find many flaws and list them out.
Helps developers find flaws earlier in the SDLC.

####8.6.1 Automatic Reviews Compared with Manual Reviews
*Automatic pros:* Scalable, finds low-hanging fruit, low incrementation cost.
*Automatic cons:* Large number of false positives and general noise. Poor at detecting bussines logic flaws, information leakage, CSRF, race conditions etc..

###8.10 Benefits of Using Source Code Analyzers

* Brand protection due to minimized risk of security exploits
* Improvement in delivering secure software
* Reduced remedation cost since you catch flaws earlier
* Assurance to bussines partners about effectiveness of security controls
* Compliance with standards and audit requirements
* Simplified security automation in the SDLC
* Improved developer skills

##8.11 Penetration Testing
Involves actively attacking an application and analys its beaviour.
OSSTMM methodology for performing security tests. It is divided into five sections which collectively tests:

* Information and data control
* Personnel security awareness level
* Fraud and social engineering control levels
* Computer and telecommunications networks
* Wireless devices, mobile devices

You can both do manual and automated Pen testing. 
Manual has the advantage of beeing able to find bussines logic flaws, but are costly and time consuming.

Black box testing is a set of activities that occurs during predeployment.

Tools for black box testing report on the following vulnerabilities:

* Improper input validation
* Command injection and buffer overflow attacks
* SQL injection
* CSS
* CSRF
* Directory traversal attacks
* Improper session management
* Improper authentication and access control

###8.11.5 Limitations and Constraints of Pen Testing Tools
You need to be logged in to the application to be able to test every part of it.
Pen testing requires a environment closly similar to production.
BUT you should not test in production.

##9 Testing Commercial off-the-Shelf Systems
Its hard to know what to do or who to contact if you find vulnerabilities in COTS systems.
To evaluation them there are som industry standards, including the Common Criteria (CC).

###9.1 The Problems with Shrink-Wrapped Software
Testing og COTS applications are often inaduqiet, leaving the customers little ability to gain confidence in the product.
Without this confidence we as users implement our own countermeasures around the existing software.
Important to document testing off application.
In the commercial world there hasent been a clear cut standard for security requirements.

###9.2 The Common Criteria for Information Technology Security Evaluation
CC is designed for use as a basis for evaluation security properies of IT products and systems.
By establishing a CC base the evaluation of a product becomes more meaningful to a broader audience of buyers.
Enables better comparabiltiy.
Establish the level of confidence that the security functions provide.
CC v3.1 consists of three parts:

* Introduction and general model
* Security functional requirements
* Security assurance requirements

CC is used to test security claims of the software manufacturer - not test if software meet some functional requirement.

In the context of CC: functional requirements describe what security services a system should do by design, assurance requirments describe how well the functional requirements should be implemented and tested.

####9.2.1 Harmonizing Evaluation Criteria
Joint efforts to harmonize security evaluation criteria world wide.
Important if companies want to sell products outside there borders without running specific security evaluations for each country.
CC address this problem through the Common Criteria Recognition Arrangement (CCRA).

CC is an approach to gaining confidence through the process of **Development**, **Evaluating** and **Operating** systems.

####9.2.2 Development
Central part of CC is the Protection Profile (PP) that allows devs and consumers to define and document sets of security requirements.

####9.2.3 Evaluation
Evaluators use what is called the Security Target (ST) as security specifications made for the product.
Goal is to determine wheter security specs (ST) of the product are met.
Evaluators then document there findings.

####9.2.4 Operation
If something is found after production you dont need to fully reevaluate the product. CC allows for Maintainance of  Assurance for incremental changes.

####9.2.5 Key Concepts of the CC

* *Protection Profile:* document that details, CC language and syntax, the security requirements for a given class of peoducts offering similar security functions (firewall, db server..). Vendors, consumers or cosnumer groups may all write PPs. 
* *Evaluation Assurance Level:* designate the specific level of assurance required for the implementation descibed in PP. 
* *Security Target:* Threats to TOE's security, security objectives, requirements and summary specs are primary input.

####9.2.6 The Security Framework
To understand CC you need to understand the framework it operates within.
Includes the following areas:

* Security environment
* Objectives
* TOE security requirements
* Security specifications
* Implementation

####9.2.7 The CC Approach
CC does not endore a specific design or development methodology, but assumes that security requriements are incorperated in the overall design of the system.

####9.2.8 The Security Environment 
To describe the environment completly the PP or ST must establish a set of assumptions about the following:

* The TOE's phisical environment, including known personnel and physical security arrangements
* The assets requiring protection, (Db or files)
* The purpose of the TOE, including its product type and its intended purpose.


**See Presentation Chapter 9 for more**

##10 Implementing Security and Resilience Using CLASP
We examine the CLASP methodology.

What are covered:

* CLASP concepts
* Overview of CLASP processes
* Key CLASP best practices
* Activities toaugment software development processes
* Applying CLASP activities to roles
* Re-engineering your SDLC with CLASP
* CLASP implementation roadmap

###10.1 Comprehensive, Lightweight Application Security Process (CLASP)
offers well-organized and structurred approach to help move security concerns into earlier stages of SDLC.
Designed to be easy to adopt.
Think of it as a resource library to avoid reinventing the wheel when you come across the need for new processes or ideas for secure sw development.
CLASP provides details on:

* Concepts behind CLASP
* Seven best practives that define CLASP
* High level security services that serve as a foundation
* Core security principles
* Abstract roles that are typically involved in software development.
* Activities to help build more secure software.
* CLASP process engineering and roadmap
* Coding guidlines
* Lexicon of common vulnerabilities

###10.2 CLASP Concepts
Designed to allow easy integration of security related activities.
Each activity is divided into process components and are linked to one or more role (project manages, developer, tester, consumer).
Vulnerability Lexicon. Allows for quick location of information from many perspectives:

* Problem type
* Categories of problem type
* Exposure periods
* Avoidance and mitigation periods
* Consequences
* Affected platforms and languags
* Risk assessment

###10.3 Overview of the CLASP Process
CLASP structure:

* CLASP views
* CLASP resources
* Vulnerability use cases

Process presented through five high-level perspectives - CLASP views
Each view is broken down into activities, which in turn contain process components.

CLASP views

1. Concepts View - Understand how CLASP process components interact and how to apply 2-5
2. Role-Based View - Create roles required by security-related proejct and utilize them in 3, 4, 5
3. Activity-Assessment View - Asses 24 security related CLASP activities for suitability in 4
4. Activity-Implementation View - Perform subset of 24 activities selected in 3
5. Vulnerability View - Integrate solutions to problem types into 3 and 4.

###10.4 CLASP Key Best Practices
The basis of all security related software development activities.

####10.4.1 BP1: Institute Awareness Programs
Educate everyone involved in the software process about essential security concepts and techniques.
Can be rapidly implemented by hiring external securty experts.
Everyone should receive general security training, and training specified to there role.
Everyone should be familiar with the security requirements of the system.
One Best practice: Address security issues during techinical meeting of the dev team.
Solving security problem can be negative on the schedule.

Appointing a security officer may be an excellent way to increase awareness. Can be rotated between different people as needed.

The security officer should have at least the first 2 of these duties:

* Serve as a repository of security expertise for other project members
* Take into account security concerns thoughout the SDLC
* Review work of other team members.

Having rewards for effective handling of security issues = awareness. Reward makes behavior into habit.

####10.4.2 BP2: Perform Application Assessment
Testing and assessment should be central components of your software security strategy.
CLASP offers detailed guidance for each of the following areas:

* Identify, implement and perform security tests
	* Find problems not found by implementation review
	* Find risk introduces by the environment
* Perform security analysis of system requirements and design
	* Assess likely risks in timely and cost-effective manner.
	* Identify high-leve threats not documented
	* Identify improper security requirements
	* Assess security impact of non-security requriements
* Perform source-level review
	* Find vulnerabilities introduces into implementation
* Reseach the security posture of technology solutions
	* Assess risks in third-party applications
	* Determine how effective it is likely to be at elevated risks
* Verify security attributes of resources
	* Confirm that software uses previously defined policies.

####10.4.3 BP3: Capture Security Requirements
Make security requirements as much of a priority as functional requirements.
Some factors that should be considered:

* An understanding of how applications will be used/misused
* The assets(data) the application will provide, and what protection level is appropriate for you business (Think about policies, regualtions and potential impact on reputation).
* The architecture of the application and attack vectors
* Potential compensating controls, and their cost/effectiveness

CLASP detailed guidance for capturing security requirements:

* Detail misuse cases
	* Communicate risks to stakeholder
	* Comminicate secuirty decisions to stakeholder
* Document security relevant requirements
* Identify attack surface
* Identify global security policy
	* Provide comparing the security posture to different products in organization
* Identify resources and trust boundaries
	* Provide a structured foundation for understanding the requirements of a system
* Identify user roles
* Specify the operational environment

####10.4.4 BP4: Implement Secure Development Practices
CLASP recommend:

* Annotate class designs with security properties
* Apply security priciples to design
	* Harden application
	* Identify risks in third-party apps
* Implement and elaborate resource policies and security technologies
* Implement interface contracts
	* unit-level sematic input validation
	* Indentify reliability errors in a structured way early as possible
* Integrate security analysis into source management process
* Perform code signing

####10.4.5 BP5: Build Vulnerability Remediation Procedures
Especially importan in context of updates and enhancements.

CLASP guidance:

* Addressing reported security issues
	* Ensure that identified security risks in an implementation is properly handled
* Managing security issue disclosure process

####10.4.6 BP6: Define and Monitor Metrics

* Monitor security metrics
	* Gauge the likely security posture of the ongoing development
	* Enforce accountability for inadequate security

####10.4.7 BP7: Publish Operational Security Guidelines
Security does not end when the application is in production.
These tips will help orginazations make the best out of the capabilities you have built into your application:

* Build an operational security guide
	* Provide customer with docs security measures to better secure the product.
	* Provide documentation for use of security functionality within the product.
* Specify db security configuration

###10.5 CLASP Security Activities to Augment Software Development Processes
Core of CLASP: 24 security-related activities that can all be integrated in the SDLC.
See page 228 for the list.

###10.6 Applying CLASP Security Activities to Roles
CLASP ties activities above with specific roles in the project.

1. Project Manager
	* Drives CLASP initiative
	* Mandates management buy-in
	* Responsibilities:
		* Promote security awareness
		* Manage metrics
		* Hold team accountable
2. Requirements Specifier
	* Maps customer features to business requirements
	* Provide NFRs
	* Responsibilities:
		* Detail security business req.
		* Attempt reuse security req across orginization
		* Specify misuse cases
3. Architect
	* Creates network an application architecture
	* Specify network security requirments
	* Responsibilities:
		* Understand security implications of used technlogy
		* Enumerate each resource in the system
		* Identify roles in the system
		* Identify basic operations on each resource
		* Help others understand relations between resources
4. Designer
	* Keep risks out of application
	* Has most security relevant work
	* Responsibilities:
		* Choose and research used technology
		* Assess consequences and how to address identified flaws
		* Document attack surface
	* Designer should:
		* Push back requirements with unrecognized risks
		* Give implementers a roadmap to minimize risk
		* Understand third-party integration risk
		* Respond to threats
5. Implementer
	* Developers
	* Responsibilites:
		* Follow coding standards, policies etc..
		* Identify and notify new risks to designer
		* Attend security awareness training
6. Test Analyst 
	* Quality assurance
7. Security Auditor
	* Examine and assure state of project
	* Responsibilities:
		* Determine if application meets security requirments
		* Find vulnerabilities in implementation

###10.7 Re-engineering Your SDLC for CLASP
Any effective process re-engineering plan should at min include these elements:

* Business objectives that the process is being developed to meet
* Project milestones
* Pass/fail criteria for each milestone

####10.7.1 Business Objectives
Remember to include global application sw development security policies in the company.
Another objective is to agree on the set of security metrics that will be collected and monitored.

####10.7.2 Process Milestones
Construct a draft plan that identifies the key proejct milestones. Focus on when activities will start, who performs them and how log to complete.

####10.7.3 Process Evaluation Criteria
Implement success critirias for your team.

* Comparing the rate of depoyment across projects
* Comparing the percentage of security faults identified in development vs production
* Monitoring timelines, accuracy and thoroughness of key artifacts.

##11 Metrics and Models for Security and Resilience Maturity
What does a maturity model provide?

* Set of metrics to use as benchmarks to state where we are and what have been done in terms of security
* Detailed description of what to do and when to do it

###OpenSAMM
* OWASP

It will aid in:

* Evaluation an organization's existing software security practices
* Building a balanced software security program in well-defined iterations
* Demonstrating concrete improvements to a security assuracne program
* Defining and measuring security activities within an organization

Offers a roadmap and well defined maturity model for secure development and deployment as well as tools fro self assessment and planning

OpenSAMM business functions

* Governance
	* The processes related to how an organization manaes overall software development activities
* Contruction
	* How organizations defin goals and creates software within development projects
* Verification
	* How orgs check and tests artifacts they produce
* Deployment
	* How orgs manage releases after software is created

####Core Practice Areas - Governance
* **Strategy & Metrics (SM):** Involves the strategic direction of measuring and tracking metrics about an organiation security posture
* **Policy & Compliance (PC):** Set up program for increased assurance in software development and in operation.
* **Education & Guidance (EG):** Increase security knowledge among staff.

####Core Practice Areas - Construction

* **Threat Assessment (TA):** Identify potential threats in software, to better understand its risk.
* **Security Requirements (SR):** Promoting inclusion of security requirements during the SDLC.
* **Secure Architecture (SA):** Bolster design process with activities to promote secure-by-default design.

####Core Practice Areas - Verification

* **Design Review (DR):** inspecting artifacts created from design process to insure security
* **Code Review (CR):** Assessment of source code to aid in flaw discovery and related mitigation activities as wellas establish a baseline for secure coding expectations.
* **Security Testing (ST):** Testing software in its runtime environment

####Core Practice Areas - Deployment

* **Vulnerability Management (VM):** Establishing consistent processes for managing vulnerability reports to limit exposure.
* **Environment Hardening (EH):** Implementing controls in operating environment to bolster security posture of deployed applications
* **Operational Enablement (OE):** Identify and capture security information needed by an operator to properly configure, deploy and run an orginizations software

####Level of Maturity

Each core practise ara has a level of maturity, each level has several components that specify the critical factors for understanding and achieving the sated level:

* **Objective:** General statement that captures the assurance goal of attaining the associated level. 
* **Activities:** Core requisites for attaining a level. Capture the core security function, and orginizations are free to determine how they fulfill the activities.
* **Results:** Capabiities oobtained by achieving the given Level.
* **Success Metrics:** Specify example measurements that can be used to see if the orginazation is performing at the given level.
* **Costs:** Expenses incurred by an organization attaining the given level. Meant to provide idea of the one-time and ongoing costs with performing on a given level.
* **Personnel:** Expenses in term of human resources within an organization attaining the given level.

####Assurance
OpenSAMM is designed for use in improving an assurance program in phases by:

* Selecting security Practices to improve in the next phase
* Achieving the next Objective in each Business Function by performing corresponding Activities by soecified Success Metrics.

###BSIMM - Building Secuirty In Maturity Model
- Intended to stimulate cultural changes about creating secure software
- Help determine maturity level in an organization
- How to improve?
- Not a How-To, but a collection of good ideas.

####BSIMM - Categories

* Governance - Strategy and Metrics ; Compliance and Policy ; Training
	* Organize, manage and measure secure initiative.
	* Its all about: Planning, Role assignment, identify goals.
* Intelligence - Attack Models ; Security Features and Design ; Standards and Requirements
	* Includespractices that results in collection of knowledge about software security activities in the org.
	* Examples: Attack models, Proactive security guidance, Creating standards for major security controls
* SSDL Touchpoints - Architecture Analysis ; Code Review ; Security Testing
	* Practices associated with analysis and assurance of software development artifacts.
	* Examples: Code review, black box testing, fuzz testing, Risk-driven white box testing
* Deployment - Penetration Testing ; Software Environment ; Configuration Management and Vulnerability Management
	* Practices that interface with traditional software and network security.
	* Software configs
	* Maintenance
	* Software environment - OS, firewalls, patching, updating..



##Appendix A - 2010 CWE/SANS Top 25 Programming Errors
Collabitation between SANS Institute,  and many top security experts in the US and Europe.
Main goal: To prevent vulnerabilities at the source by educating programmers how to eliminate them before software is shipped.

The list is categories into 3 sections:

### Insecure Interaction Between Components
Rank | Name
---- | ----
1 | XSS
2 | SQL Injection
4 | CSRF
8 | Unrestricted Upload of dangerous files
9 | OS Command Injection
17| Exposing info through Error messages
23| Open Redirect
25| Race Condition

### Risky Resource Management
Rank | Name
---- | ----
3 | Classic Buffer overflow
7 | Path Traversal
12| Buffer access with incorrect Length Value
13| Improper checks for Unusual or Exceptional Conditions
14| Improper Control of Filename for include/require statement in PHP
15| Improper validation of array index
16| Integer Overflow
18| Incorrect calculation of buffer size
20| Download of code without integrity check
22| Allocation of Resources without limits

### Porous Defenses
Rank | Name
---- | ----
5 | Authorization
6 | Reliance of input in security decisions
10| No encryption
11| Use of Hard-Coded Credentials
19| Missing Authentication for critical functions
21| Incorrect permission assignment
24| Use of Broken crypto algorithm

##Appendix B - ESAPI

Includes a set of security control interfaces. A reference implementation for each secuirty control.
Each Interface is mapped to the OWASP Top 10

###B.1 Interface Encoder
- Encoding and Decoding
- Expects canonicalized input
- Whitelist security model

###B.2 Interface Validator
- Canonicalize and validates untrusted input

###B.3 Interface User
- Represents a user account
- Key component ( is account locked, enabeled, expired ?)

###B.4 Interface Authenticator
- Generates and manages account credenrials and session identifiers

###B.5 Interface Access Controller
- Handles access to resources

###B.6 Interface AccessReferenceMap
- Used to avoid direct object references

###B.7 Interface Encryptor
- Cryptography

###B.8 Interface HTTPUtilities
- Collection of methods related to HTTP security
	- Requests, response
	- session
	- cookie

###B.9 Interface Logger

##Quotes explained:
"Morris worm": Brought roughly 10% of the internet services in 1988 to a complete halt.

"Nokia 1100": A few years after it hit the market it suddenly spiked in demand, people offered
several thousand for this model. The reason beeing a vulnerability which let it be reprogrammed to
use someone elses number, and get that numbers SMS etc. Many services uses SMS code as part of security system.

##Acronyms:
CERT - Computer Emergency Response Team
SEI - Software Engineering Institute


INF226-ProjectPres-Group5-H14.pdf