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
Potential impact: Unauthorized access to stored data might result in privacy violations, data theft, or unauthorized disclosure of sensitive information.     
Associated Risks: Without encryption, stored data is subject to unwanted access via a variety of attack vectors, such as device compromise or data transfer interception. This puts users at danger of identity theft, financial loss, or reputational damage.



