# Cross Platform Security

## Security Assessment

### 1. Insecure data storage:
The application uses AsyncStorage for storing notes. AsyncStorage is not protected/encrypted by default, therefore any sensitive data stored in it can be easily retrieved if the device is compromised.    
The notes are stored using AsyncStorage without encryption which leaves them exposed to unwanted or unauthorized access.    
```
// Notes.tsx     
import AsyncStorage from '@react-native-async-storage/async-storage';

// Function to store notes   
private async storeNotes(notes: INote[]) {   
    const suffix = this.props.route.params.user.username + '-' + this.props.route.params.user.password;   
    const jsonValue = JSON.stringify(notes);   
    await AsyncStorage.setItem('notes-' + suffix, jsonValue);   
}   

// Function to retrieve notes   
private async getStoredNotes(): Promise<INote[]> {     
    const suffix = this.props.route.params.user.username + '-' + this.props.route.params.user.password;     
    const value = await AsyncStorage.getItem('notes-' + suffix);     
    if (value !== null) {    
        return JSON.parse(value);     
    } else {    
        return [];     
    }     
}
```   
Recommendation: Encrypt sensitive data before storing it in AsyncStorage with encryption libraries such as react-native-keychain or react-native-sensitive-information. You can also build appropriate access controls to limit access to stored data.

### 2.	Improper authentication:
We can say that the authentication mechanism in the app is little weak. It compares the entered username and password with hardcoded values stored in the code.    
The ‘Login’ component's hardcoded credentials (‘users’ array) make it easy for attackers to get unauthorized access if they reverse engineer the program.

```
// Login.tsx
const users: IUser[] = [
    { username: 'joe', password: 'secret' },
    { username: 'bob', password: 'password' },
];

function login() {
    let foundUser: IUser | false = false;

    for (const user of users) {
        if (username === user.username && password === user.password) {
            foundUser = user;
            break;
        }
    }

    if (foundUser) {
        props.onLogin(foundUser);
    } else {
        Alert.alert('Error', 'Username or password is invalid.');
    }
}
```
Recommendation: Implement a stronger authentication system, such as token-based authentication using JWT (JSON Web Tokens) or OAuth. Credentials should be stored securely, preferably hashed and salted, rather than hardcoded in application code.

### 3.	Code Injection:
The ‘evaluateEquation’ function in the ‘Note’ component uses ‘eval’ to evaluate the math equation entered by the user. This is extremely unsafe since it can execute arbitrary code injected by evil users, resulting in security vulnerabilities such as code injection attacks.

```
// Note.tsx
function evaluateEquation() {
    const result = eval(props.text);
    Alert.alert('Result', 'Result: ' + result);
}
```
Recommendation: Avoid using ‘eval’ for running dynamic code as it can lead to code injection vulnerabilities. Instead, you can go for safer alternatives like ‘parseInt’ or ‘parseFloat’ for numerical operations or a parser library for evaluating expressions.

### 4. Insufficient Input validation:
The software TotallySecureMathApp lacks appropriate input validation, particularly in the ‘Login’ and ‘Notes’ components. Input fields should be checked to avoid injection attacks like SQL injection and cross-site scripting (XSS).     
The Note component does not validate the input for the math equation before evaluating it using eval. This can result in unexpected behavior or security risks.
```
// login.tsx
<TextInput
    style={styles.username}
    value={username}
    onChangeText={setUsername}
    placeholder="Username"
/>
<TextInput
    style={styles.password}
    value={password}
    onChangeText={setPassword}
    placeholder="Password"
/>
```
Recommendation: Implement input validation to guarantee that user-provided data is in the correct format and does not contain malicious input. Use libraries or built-in routines to validate and sanitize input.

### 5. Insecure code practices:
Storing sensitive information (such as passwords) in plain text (even within code) is risky. Passwords should be hashed and salted before being stored.     
Using ‘eval’ to examine user-supplied input (‘props.text’ in ‘Note’) is strongly discouraged owing to potential security issues.     
The absence of effective error handling and logging tools might make it difficult to notice and respond to security incidents or vulnerabilities.    
```
// login.tsx
const users: IUser[] = [
    { username: 'joe', password: 'secret' },
    { username: 'bob', password: 'password' },
];
```
Recommendation: Encrypt and hash important information to ensure its security. Avoid using eval to execute dynamic code; instead, use safer alternatives such as parser libraries or built-in arithmetic functions.     
Addressing these vulnerabilities and applying the recommended procedures will dramatically improve the security posture of the Totally Secure Math app. Regular security assessments and code reviews should also be carried out to detect and address emerging threats and vulnerabilities.

## Documentation of vulnerabilities
### Title: 
Comprehensive Security Vulnerability Assessment of the Totally Secure Math App.
### Abstract: 
This study provides a thorough security assessment of the Totally Secure Math app, revealing serious weaknesses that jeopardize its integrity, confidentiality, and availability. Each vulnerability is rigorously researched, with detailed descriptions, potential impact, related risks, and mitigating solutions. By resolving these weaknesses, the app can improve its protections and efficiently protect user data.
#### 1. Insecure Data Storage:

Description: The app uses AsyncStorage to store user-generated notes without encryption.     
Potential Impact: Unauthorized access to stored data might result in privacy violations, data theft, or unauthorized disclosure of sensitive information.     
Associated Risks: Without encryption, stored data is subject to unwanted access via a variety of attack vectors, such as device compromise or data transfer interception. This puts users at danger of identity theft, financial loss, or reputational damage.

#### 2. Improper authentication:

Description: Weak authentication mechanisms rely on credentials that are hardcoded into the application code.     
Potential Impact: Weak authentication techniques raise the risk of credential stuffing attacks, unauthorized access, and account takeover.     
Associated Risks: Hardcoded credentials can be easily discovered using reverse engineering or network traffic interception, allowing attackers to breach user accounts and gain unauthorized access to sensitive data. This poses a serious threat to user privacy and security.     

#### 3. Code Injection.

Description: The software uses the eval function to evaluate user-supplied arithmetic equations without sufficient input validation.     
Potential Impact: Code injection attacks could result in the execution of arbitrary code within the app, jeopardizing data integrity and user security.     
Associated Risks: Attackers can use code injection vulnerabilities to run malicious code, resulting in unauthorized access, data manipulation, and device compromise.     

#### 4. Insufficient Input Validation.

Description: The app lacks sufficient input validation, allowing users to enter any data without validation.     
Potential Impact: Injection attacks, such as SQL injection or cross-site scripting (XSS), might jeopardize data integrity or allow unwanted access.     
Associated Risks: Without sufficient input validation, attackers may introduce malicious code or malformed data into input fields, exploiting vulnerabilities and jeopardizing app security.

#### 5. Insecure Coding Practices:

Description: Insecure coding techniques include storing sensitive data in plain text and utilizing eval to execute dynamic code.     
Potential Impact: Sensitive information exposure and code injection flaws undermine the app's security posture, increasing the chance of unauthorized access or data breach.     
Associated Risks: Storing sensitive information in plain text makes it vulnerable to unauthorized access, whilst utilizing eval increases the possibility of executing malicious code, jeopardizing app integrity and user security.      

### Conclusion:
The identified flaws threaten the Totally Secure Math app's security and integrity. To successfully prevent these threats, severe security measures must be implemented, such as data encryption, strong authentication systems, input validation, and adherence to safe coding techniques. By prioritizing security enhancements and taking a proactive risk management strategy, the app may strengthen its defenses, protect user data, and maintain user trust and confidence.

## Implementing security measures:
a. Modify the app to store sensitive data using encryption and secure storage:
```
// Modify the storeNotes function in notes.tsx to encrypt sensitive data before storing
import { encryptData } from './encryptionUtils'; // Import encryption utility function

private async storeNotes(notes: INote[]) {
    const suffix = this.props.route.params.user.username + '-' + this.props.route.params.user.password;
    const jsonValue = JSON.stringify(notes);
    const encryptedData = encryptData(jsonValue); // Encrypt sensitive data
    await AsyncStorage.setItem('notes-' + suffix, encryptedData);
}
```
b. Implement secure authentication practices:
```
// Implement token-based authentication instead of hardcoded credentials in login.tsx
// Use secure token storage mechanisms like AsyncStorage or SecureStore for storing tokens

// Example implementation using AsyncStorage
import AsyncStorage from '@react-native-async-storage/async-storage';

async function login() {
    // Perform authentication
    // If authentication successful, generate a secure token
    const token = generateSecureToken();

    // Store token securely
    await AsyncStorage.setItem('authToken', token);

    // Redirect to authenticated screen
}
```
c. Implement proper input validation and sanitization techniques:
```
// Add input validation in login.tsx to mitigate injection vulnerabilities
function login() {
    // Validate username and password inputs
    if (!username || !password) {
        Alert.alert('Error', 'Username and password are required.');
        return;
    }

    // Perform authentication
}
```
d. Identify and rectify insecure code practices:
```
// Remove hardcoded credentials and implement secure token-based authentication in login.tsx

// Example of secure token-based authentication implementation
async function login() {
    // Perform authentication
    if (authenticationSuccessful) {
        // Generate a secure token
        const token = generateSecureToken();

        // Store token securely
        await AsyncStorage.setItem('authToken', token);

        // Redirect to authenticated screen
    } else {
        Alert.alert('Error', 'Authentication failed. Please try again.');
    }
}

// Implement secure error handling practices throughout the app
// Ensure access control measures are in place to restrict unauthorized access to sensitive functionalities
```
e. Preventing code injection:
```
function Note(props: IProps) {
    function evaluateEquation() {
        try {
            // Securely parse and evaluate the math equation
            const result = parseAndEvaluateEquation(props.text);

            Alert.alert('Result', 'Result: ' + result);
        } catch (error) {
            Alert.alert('Error', 'Invalid equation.');
        }
    }

    function parseAndEvaluateEquation(equation: string): number {
        // Validate the equation and evaluate it securely
        // Example: use a library like math.js for parsing and evaluating math expressions
        // Here's a basic implementation using math.js:
        const math = require('mathjs');
        return math.evaluate(equation);
    }
}
```
## Importance of security measures:
1. Encrypting Sensitive Data: Encrypting sensitive data before saving it in AsyncStorage assures that attackers cannot read or use the data even if they gain unauthorized access. This protects against privacy violations, data theft, and unauthorized disclosure of sensitive information.        
2. Implementing Secure Authentication: Using token-based authentication and secure token storage technologies improves the app's authentication process. It lowers the danger of credential-based attacks, such as brute force assaults or credential stuffing, by removing hardcoded credentials and implementing a more secure authentication system.       
3. Proper Input Validation and Sanitization: Using input validation and sanitization techniques helps to reduce injection vulnerabilities like SQL injection and cross-site scripting (XSS). By verifying and cleaning user inputs, the app can prevent malicious input from compromising data integrity or generating unexpected behavior.       
4. Addressing Insecure Code Practices: Removing hardcoded credentials and avoiding insecure coding practices, such as using eval for code execution, strengthens the overall security of the app. Storing sensitive information securely and avoiding potentially dangerous code execution practices reduces the attack surface and minimizes the risk of exploitation.        

## Reflection on Lessons Learned:
I learned several important lessons while finding and correcting security issues in the Totally Secure Math app.        

1. The Importance of Secure Coding Techniques: Insecure coding techniques, such as storing sensitive information in plain text or utilizing eval to execute code, can pose serious security threats. Building secure apps requires adhering to secure coding techniques such as encryption, input validation, and the avoidance of risky functions.         
2. Continuous Security Assessment: Regular security assessments and code reviews are required to detect and address security issues in a timely way. Security is a continual process, and periodically assessing the app's security posture helps to guarantee that it is resilient to evolving threats.        
3. User Education and Awareness: Educating users on best security practices, such as using strong passwords and exercising caution when disclosing personal information, can help reduce security risks. Furthermore, giving users clear instructions on how to secure their data and privacy within the app helps improve overall security.

## Practices to mitigate potential risks:
1. Security by Design: Including security considerations in the app's design and development process from the start ensures that security is an integral part of the application architecture. This includes assessing security concerns at every level of development and putting in place suitable security measures.         

2. Regular Security Testing: Conducting regular security testing, including as penetration testing and vulnerability assessments, allows you to uncover and address security flaws proactively. Potential vulnerabilities can be found and addressed before they are exploited by attackers by analyzing the app's security posture on a regular basis.         

3. User Privacy and Data Protection: Prioritizing user privacy and data protection by adopting strong encryption, secure authentication systems, and rigorous access controls fosters user confidence while also ensuring compliance with privacy rules.

## Conclusion:
Finally, the full security vulnerability evaluation of the Totally Secure Math app revealed major flaws that jeopardize its integrity, confidentiality, and availability. From insecure data storage methods to incorrect authentication techniques and code injection vulnerabilities, the app's security posture necessitates rapid attention and action. Each detected vulnerability has considerable dangers, ranging from unauthorized data access to potential code execution attacks, emphasizing the critical necessity for strong security measures.         

By resolving the detected vulnerabilities and applying the recommended security measures, the Totally Secure Math app can improve its security posture and protect user data from a variety of threats. Measures such as encrypting sensitive data before storage, establishing secure authentication processes, and ensuring correct input validation and sanitization techniques are critical for limiting potential risks and strengthening the app's defenses against attacks.  

Moving forward, prioritizing security by design, conducting frequent security testing, and focusing user privacy and data protection will be crucial for preserving the app's security resilience in the face of changing threats. By taking a proactive approach to security and regularly reviewing and upgrading its security posture, the Totally Secure Math app can effectively protect user data, preserve user trust and confidence, and reduce potential dangers in today's ever-changing cybersecurity environment.


## References:
1. React Native AsyncStorage: https://reactnative.dev/docs/asyncstorage
2. React Native Keychain: https://github.com/oblador/react-native-keychain
3. React Native Sensitive Information: https://github.com/Traviskn/react-native-sensitive-info
4. JSON Web Tokens (JWT): https://jwt.io/
5. React Navigation: https://reactnavigation.org/
6. Math.js Library: https://mathjs.org/
7. IEEE Computer Society, "IEEE Guide for Software Vulnerability Analysis," IEEE Std 1659-2018, 2018.
8. OWASP, "OWASP Mobile Security Testing Guide," https://owasp.org/www-project-mobile-security-testing-guide/
9. H. Díaz, S. Castellanos, R. Cruz, "Cross-Site Scripting (XSS) Vulnerabilities in Web Applications: A Systematic Literature Review," in IEEE Access, vol. 7, pp. 10958-10976, 2019.
10. D. Shah et al., "Cross-Site Scripting Vulnerabilities: A Quantitative Study," in 2015 IEEE 27th International Conference on Tools with Artificial Intelligence (ICTAI), 2015, pp. 135-142.


