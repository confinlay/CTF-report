# Casper CTF: Report
The following is a report I wrote for a CTF-style project I completed as part of a course on the "Development of Secure Software". The first 3 vulnerabilities are memory safety issues in C programs, and the following 5 vulnerabilities are SQL injections performed on a web application that what provided to us by the faculty.

## Memory Safety Vulnerabilities

### Casper5 Solution

#### Description

Casper5 is a program that initializes a `user_t` struct and assigns the user-provided command line argument to the `name` field of this struct. It then checks if the `authority` field in the `role_t` struct nested within the `user_t` struct is equal to 1. If it is, the user is granted additional privileges and is dropped into a shell.

The important structs and variables in this program are organized as follows, all allocated on the stack:

- A `user_t` struct "`thisUser`" containing the following fields:
  - A buffer `name` of 775 characters, intended to contain the input of the user
  - A `role_t` struct "`role`", which contains the following fields:
    - A buffer `rolename` of 32 characters, intended for containing a description of the role in question
    - An int `authority`, intended for indicating the privileges of the role in question

The program first initializes a `user_t` struct and sets its role to the default role where the authority int is equal to 0. Next, it copies the content from the command-line argument provided by the user into the `name` field of the `role` struct.

#### Vulnerability

The vulnerability in this program arises because the `strcpy` call on line 19 does not limit the length of the source of the copy, reading from this source until it encounters the null terminator (`\0`). Given that the source of this copy is the command line argument, provided by the user, the user can provide a longer input than fits the size of the buffer, and thus overwrite other data on the stack.

#### Exploit Description

To exploit this vulnerability, we will aim to overwrite the value of `authority` (which will default to 0) with the value 1, granting us admin privileges. By observing the order of allocation of the target variables during the execution of the program, we can predict where they will lie on the stack.

The `role` pointer in `thisUser` is allocated directly after the `name` buffer. Given that our command line argument `argv[1]` will be insecurely copied into this `name` buffer, we can overflow the buffer and thus overwrite the memory location pointed to by `role`. When the fields within the `role` struct are accessed by the main program, the data stored at the memory location pointed to by the `role` pointer will be accessed. The first 32 bytes of information after the memory address pointed to by `role` will correspond to the inconsequential `rolename` buffer, with the next 4 bytes of information after this corresponding to the `authority` field.

We cannot include an int value of 1 in our input since that would involve writing null bytes (which terminate strings), so we must find a location in a static segment of memory which contains a value of 1, and overwrite `role` to point to the memory location 32 bytes before it. In our implementation, this corresponds to the following input as a command-line argument to the program: `python -c 'print("X"*776+"\x84\x99\x04\x08")'` (i.e., 776 'X' characters to fill the buffer followed by the memory address `0x08039984` appended in reverse order).

When this input is copied into `name`, this will overwrite the `role` pointer and cause `authority` to contain a value of 1. This is the condition we need to be granted admin privileges and launch a shell.

#### Mitigation

The first and most obvious mitigation tactic for this vulnerability would be to replace the insecure function `strcpy()` with the safer alternative `strncpy()`. This function accepts an additional parameter which specifies the maximum number of characters to copy, thereby preventing buffer overflow. It's worth mentioning, however, that an attempt to overflow the buffer will result in an absence of a null terminator in the resulting string variable. Therefore, the last character in the resulting string should be manually set to the null terminator before it is used to prevent undefined behavior in the program.

An additional mitigation measure in this case would be to implement Address Space Layout Randomization (ASLR), whereby runtime memory addresses are arbitrarily varied between executions. Since the attacker cannot write null bytes into memory via the command line argument (apart from the null terminator appended to the end of their input), it will be challenging for them to reliably place a value of 1 (`0x0001`) into `authority` when the values at arbitrary memory locations change between executions, and thus memory leaked during one execution will not help them exploit the vulnerability at the next execution.

### Casper7 Solution

#### Description

Casper7 is a simple program which takes asks the user for their name, takes in user input, and, finally, prints a greeting message to the user which includes their name. The program has one important variable:

- A buffer `buf` of 775 characters, intended for storing the name of the user (the user input).

#### Vulnerability

While the stack is non-executable in this program, it is still vulnerable to a jump-to-libc attack, whereby the return address of a function is overwritten with the address of a C library function, which can be used to change the behavior of the program. A common target function is the `system()` function, which will run the command provided to it as an argument. If the attacker can manipulate the argument to this call to the `system()` function, they may be able to drop themselves into a shell, thereby compromising the system.

#### Exploit Description

In our case, the goal is to be dropped in the /bin/xh shell. The best way to provide this as an argument to the `system()` function would be to store it in an environment variable, to be accessed by memory address later. Since this environment variable does not exist yet, we make it with `export MYSHELL=/bin/xh`. Next, we investigate the overflow of the buffer containing user input. While the buffer is 775 characters long, this buffer will not necessarily be located right next to the return address of greetUser() on the stack, so some trial-and-error attempts reveal that 791 filler characters must be provided at the beginning of the user input in order to begin overwriting the return address of greetUser(). The next input should be the address of the `system()` function, in our case this is `0xb7e1a420`. Next, we provide the address of our environment variable as an argument to the `system()` function call. This can change depending on the execution environment, so we write a C program which gets this address using `getenv()`. If we want to avoid our exploit being detected, we should provide the address of the C library function `exit()` to `system()` so that it exits silently. To do this, we instead provide 787 filler characters to the buffer, followed by the address of `exit()`, and then the address of `system()`, and, finally, the address of our environment variable containing "/bin/xh". Once all this is coordinated correctly, we are dropped into a shell as expected.
It's worth noting that it was found that the text `/bin/xh` was located at a constant offset of 18 from the address returned by `getenv()`. The C program for finding the memory location of the environment variable was altered to add 18 to this address before returning it (this was as simple as `address += 18;`).

#### Mitigation

First and foremost, insecure functions like `gets()` should be replaced with `fgets()`, which allows the developer to specify how many characters should be read in from the user. This can prevent the attacker from overflowing the buffer.
In addition, stack canaries should be used to prevent the return addresses of functions in the program from being overwritten by the attacker. These special values are placed just before the return addresses of functions in the program and, if they are altered, the program will terminate.
ASLR (Address Space Layout Randomization) will make it more difficult for the attacker to predict the memory locations of environment variables/C library functions, but will not prevent the attack entirely.
Finally, Control Flow Integrity (CFI) checks done by the compiler can restrict the call state from which certain types of functions can be called. These sorts of mechanisms could prevent a C library function from being called from an unexpected location in the program (in this case, from greetUser()).

### Casper8 Solution

#### Description

Casper 8 is a program that takes in user input in the form of a command line argument and prints out a message "Hello [name]!" where `name` is the user input. It does this by allocating an empty buffer of 775 characters, writing the formatted string into it using `sprintf()`, and then printing the contents of the buffer. After this greeting, the program checks whether the `isAdmin` int variable is equal to zero. It should be, as it is initialized to 0 before the execution of the main function and is never (explicitly) changed. In the case where `isAdmin` is not equal to 0, the user is granted admin privileges and dropped into a shell. The 2 important variables in this program are as follows, all allocated on the stack:

- An int `isAdmin`, intended for indicating whether the current user is an admin.
- A buffer `buf` of 775 characters, intended to contain the output string for printing to the console.

#### Vulnerability

This program is vulnerable to a format string vulnerability at the `sprintf` call on line 9. When a format string function is called, the program pushes each of its arguments onto the stack, followed by the string itself. When a format specifier is found in the string, the function will turn to the previous memory addresses to find the argument corresponding to the specifier in question. However, if fewer arguments are provided than format specifiers, the function will keep reading from previous memory locations on the stack and access memory not designated for this function call. This can lead to data leaks and undefined behavior in the program. If the user includes format specifiers in their input, they can cause this behavior. With format specifiers like `%x`, the user can read from previous locations in memory and with `%n`, the user can even write to memory and implement a data-only attack.

#### Exploit Description

Given that all the attacker needs to do is write *any* value other than 0 into `isAdmin` in order to launch a shell, the exploit does not need to maintain a high level of precision. The first step is to identify the memory location of the int variable `isAdmin`. Because this is a global variable, it will be located in the .bss of the binary. Since ASLR is not enabled, we can find its memory location using the following command and save it for later: `objdump -t ./casper8 | grep isAdmin`.

Now that we have the memory location of `isAdmin`, we turn to the exploitation of the format string vulnerability. Our exploit relies on the `%n` format specifier. This specifier counts the number of characters in the string up to this point (i.e., the size of the string so far) and writes this to the memory location pointed to by the argument. If we can design our input so that this argument is the memory location of `isAdmin`, then `%n` will write an arbitrary value to `isAdmin` and our exploit will succeed.

If we want our command line argument to provide the memory address of `isAdmin`, we need to find out where this argument sits in relation to this string (i.e., which argument should we specify to `%n` to use so that it accesses our command line argument? The 8th argument? The 9th argument? It is worth noting that only 1 argument is actually provided to this format string function, so we are really distinguishing between previous locations on the stack). By using the `%x` format specifier, we can print the values held in the previous memory locations on the stack to the command line. If we include an identifiable character sequence at the start of our input (e.g., XXXX), we can provide an argument like `python -c 'print("YXXXX" + "%x_"*25 )'` and discover that our input is located in the place of the 11th argument to this format string function given an offset of 1 character (this is because `0x58585858` can be observed after 10 previous values are printed to the command line with `%x`).

With this information, we can begin our input with the memory location of `isAdmin`, followed by the format specifier `%11$n` (the 11 telling the format specifier to write to the memory location pointed to by the 11th argument to the format string function), and our exploit should succeed. When we provide the following input `python -c 'print "Y\x9c\x99\x04\x08%11\$n"'`, our exploit succeeds and we are dropped into a shell.

#### Mitigation

In order to prevent against format string attacks, user input should never be directly printed using `printf()`. Instead, the user input should be provided as an argument to a string with a format specifier included for printing the user input. In this case, that would mean replacing `printf(buf)` with `printf("%s", buf)`. This will cause the format specifiers in the user input to be printed out as text rather than interpreted as formatted specifiers in the string by the program.

## Web Vulnerabilities

### First SQL Injection (`exploit-sqli-1.sh`)

#### Description

The first injection occurs at the login page to the website, located at the following URL: [https://dss-lab.edu.distrinet-research.be/login](https://dss-lab.edu.distrinet-research.be/login). This page has form fields for the email and password of the account you are attempting to login to. When the "submit" button is pressed, the inputted values are sent to the server in the form of URL parameters and the server-side application runs an SQL query to find a user object whose attributes "email" and "password" match those inputted by the user. If there is a match, the current user is logged in to that account. For the rest of the session, the current user will have a cookie which allows them to remain logged in without re-inputting the email and password.

#### Vulnerability

The server-side application checks a username and email match with the following SQL query: `SELECT * FROM users WHERE email = '[email input]' and password = ‘[password input]’`, with the following characters/sequences prohibited from being included in the email input: `'admin', ;, ' ' (a space), |, &, +`. The vulnerability arises from the fact that the attacker can format their input in the "email" field to cause the rest of the query after this field to be commented out, resulting in the query returning a match as long as a user with the given email exists, regardless of password (i.e., the password check is bypassed).

#### Exploit Description

The simplest way to implement this exploit would be to enter “west.ada@example.com’ -- “ into the email field, with the single quote causing the server-side application to read the double-hyphen as SQL syntax, not user input, and thus commenting out the password check. However, the forbidden characters in the input (which include the space character) will be filtered out by the application, and so we need to find some workarounds.

While space characters are not allowed in the input, which prevents the comment syntax "—" to be made valid with a subsequent space, any whitespace character will do. As such, a tab character can be used following the double hyphen (encoded as `%09` in a URL). While the server-side application appears to filter out trailing whitespace characters at the end of the input, we can append any character to the input (say, "x") to cause the tab character to be included following the double hyphen. The endpoint for running this query is the following: [https://dss-lab.edu.distrinet-research.be/authenticate?email=[email]&password=[password]](https://dss-lab.edu.distrinet-research.be/authenticate?email=[email]&password=[password]), so our curl command will provide the following for the email parameter `west.ada%40example.com%27%09--%09x` and anything for the password (this is the case that we attempt to sign in to the email 'west.ada@example.com' observed from elsewhere on the public-facing website). The server-side application will thus run the following query: `SELECT * FROM users WHERE email = 'west.ada@example.com’ -- x’ AND password = x`, returning our target user without checking the password.

### Second SQL Injection (`exploit-sqli-2.sh`)

#### Description
The second SQL injection occurs on the course pages when logged in as a user, accessible via the URL: `https://dss-lab.edu.distrinet-research.be/course/[x]` where `x` is the course number (e.g., 2). This page includes course information and a list of all posts. A form field allows users to search for posts by titles or content. The server-side application runs an SQL query to find matching posts.

#### Vulnerability
The application uses the query: `SELECT * FROM posts WHERE (title LIKE '%[input]%' OR content LIKE '%[input]%') AND course_id = [current course id]`, with certain characters/sequences like `"LIKE", "UNION", "SELECT", ";", "--"` prohibited in the user input. This vulnerability stems from the ability to alter the query's logic with carefully formatted input.

#### Exploit Description
By inputting `fakes%' OR 1=1) OR (title = '%fake`, we can change the Boolean logic of the query. This input makes the query return all posts in the database, bypassing restrictions on access.

### Third SQL Injection (`exploit-sqli-3.sh`)

#### Description
The third SQL injection occurs at the enrolment page of the website. When signed in as a student, navigating to `https://dss-lab.edu.distrinet-research.be/course/enroll` provides a form field for input and an “enroll button”. If the user possess the secret code to join a course, they can input it into the field and, upon pressing enroll, they will be added to this course. 

#### Vulnerability
The server-side application selects a course based on the inputted course_code with the following query: `SELECT * FROM courses WHERE join_code = ‘[input]’`, where the following characters/sequences are prohibited from the user input: `OR, AND, LIKE, LIMIT, -, =, ;, true, false`. The vulnerability here is that the prohibited character sequences do not prevent a `UNION SELECT` injection, whereby the result from this `SELECT` query can be combined with the result from another `SELECT` query, designed by the attacker. If this second `SELECT` query has looser conditions for returning a course, the attacker can enroll in a course without knowing its course code.

#### Exploit Description
If we use a `UNION SELECT` query with a `UNION SELECT` condition which is always true, the query will return all courses. While we cannot use the `=` operator, we can use several other operators (e.g. `<`). We can form a query which is always true with the following input: `2’ UNION SELECT * FROM courses WHERE ‘a’ < ‘b` . This will return all courses, but will not produce any desirable behaviour in the platform (from the attackers point of view) because the query is only expecting one object (i.e. one course). Since we cannot use the `LIMIT` keyword, we cannot choose a course at random. 

However, we can use the fact that slightly different error messages are received when no courses are returned vs. when more than one course is returned (“`SOMETHING WENT WRONG: More than one record returned`” vs. “`SOMETHING WENT WRONG: course not found`”) to slowly move toward a query which will return only one course. Take this input for instance : `2' UNION SELECT * FROM courses WHERE join_code < '2 `} - it will return no courses. So, we can deduce that all join_codes are (lexicographically) greater than the ASCII character ‘2’. If we continue to increase the ASCII value of this character input, we will find that no join_codes are less than ‘D’, but more than one is less than ‘E’. So, we move to the second character. Applying the same procedure, we find that only one join_code is less than ‘Dk’. 

So, providing `2' UNION SELECT * FROM courses WHERE join_code `<` 'Dk `} as user input causes the following query to be run on the server-side application: `SELECT * FROM courses WHERE join_code = ‘2' UNION SELECT * FROM courses WHERE join_code < 'Dk'` . This returns one course, which the attacker is enrolled in, and so the attacker has enrolled in a course without possessing the secret join_code.

### Fourth SQL Injection (`exploit-sqli-4.sh`)

#### Description
The fourth SQL injection occurs at the course pages of the website, when logged in as a teacher. This is located at the following URL: `https://dss-lab.edu.distrinet-research.be/course/[x]` where x is the number of the course (e.g. 2). As mentioned for the second injection, this page contains information about the course, as well as a list of all posts from this course, however, when the user logged in is a teacher, the page has an extra section below the posts. This section contains a list of students enrolled in this course, as well as a form field which, when "ADD" is pressed, sends the text input to the server-side application which runs an SQL query to find a user with the inputted email. However, currently the option of adding a student by email is disabled (`You cannot add a user by email yet, sorry!`).

#### Vulnerability
The server-side application selects the student id returned based on the user's input with the following SQL query: `SELECT id FROM users WHERE email = '[input]'`, with the following characters/sequences prohibited in the user input: `OR, AND, LIKE, WHERE, HAVING, IN, (, ), -, =, &, |, true, false, /, * or ;` .
The vulnerability here is that the prohibited character sequence do not prevent a `UNION SELECT` injection, whereby the result from this `SELECT` query can be combined with the result from another `SELECT` query, designed by the attacker. Similarly to in the third injection, if the second `SELECT` query has looser conditions (or no conditions at all for that matter) for returning a student id,  then the attacker can add a student to the course in a manner not condoned by the system.

#### Exploit Description
If we use a `UNION SELECT` query with no `WHERE` condition, the query will return all user id's. This will comply with the input limitations by not using the `WHERE` keyword. However, the application only expects one student id to be returned by the query, so we will append `LIMIT 1` to our query so that it only returns one of the id's it would otherwise return. So, our input will look like this:  `fake' UNION SELECT id FROM users LIMIT 1 #`. While the traditional comment characters `--` and `/*` are prohibited from the input, this does not prevent us from using the `#` character to comment out the trailing quote from the input. The query formed by the server-side application with this input will be the following: `SELECT id FROM users WHERE email = 'fake' UNION SELECT id FROM users LIMIT 1 #'`. This will cause any student on the system to be chosen at random and added to the course, without requiring knowledge of said student's email or for the system to be designed to allow this behaviour (adding a user by email).

### Fifth SQL Injection (`exploit-sqli-5.sh`)

#### Description
The fifth SQL injection occurs at the same location as the first injection, at the login page, which is located at the following URL: `https://dss-lab.edu.distrinet-research.be/login`. See _1.1 Description_ for a detailed description of the behaviour of this page.

#### Vulnerability
As in the first injection, the server-side application checks a username and email match with the following SQL query: `SELECT * FROM users WHERE email = ’[email input]’ and password = ‘[password input]’`, with the following characters/sequences prohibited from being included in the email input: `’admin’, ;, ’ ’ (a space), —, &, +`. In addition to requiring the correct password for login, the query has been designed to prevent admin login from this public-facing webpage by prohibiting the word "admin" from appearing in the email input. Aside from the previously discussed password-bypass vulnerability, this location contains the additional vulnerability that admin login prevention is implemented by disallowing the character sequence 'admin' from appearing in that exact order in the input (the admin email includes the word 'admin'). This does not prevent the attacker from using an SQL function like `CONCAT()` to bypass this filter, thereby gaining access to the admin account privileges.

#### Exploit Description
In the first instance, the admin account email is found by learning a teacher's email from any course page when logged in as a student and using the first injection to log in to this teacher's account. When logged in as a teacher, the admin email is displayed at the top of the courses page (`Hello teacher, we're sorry about the recent problems on our platform! In case you are still experiencing problems please feel free to reach out to admin@dss-graiding.org.`). 

We then perform the same password-bypass exploit as in the first injection, with the added detail of using `CONCAT('ad','min@dss-graiding.org')` to ensure that the character sequence 'admin' does not appear in our input. Careful placement of single quotes `'` ensures that the server-side application interprets our CONCAT keyword as SQL syntax and not string text. The endpoint for running this query is `https://dss-lab.edu.distrinet-research.be/authenticate?email=[email]&password=[password]`, and so we provide the following email parameter: `fake%27%09OR%09email%3DCONCAT%28%27ad%27%2C%27min%40dss-graiding.org%27%29%09--%09x`. This will result in the following SQL query being run on the server: `SELECT * FROM users WHERE email = ’fake' OR email=CONCAT('ad','min@dss-graiding.org') -- x' AND password = ‘x’`. This will log us into the admin account, despite no knowledge of the password and the system being designed to prevent admin login from this endpoint, and give us access to the "admin panel", thereby compromising the security of the system.

