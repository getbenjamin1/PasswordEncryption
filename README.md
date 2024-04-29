# PasswordEncryption
Password encryption using salting before hashing 

This code encrypts passwords by generating a random 16-byte salt using SecureRandom, the salt along with the user's password, is used to create KeySpec. The password is then hashed using the PBKDF2WithHmacSHA1 algorithm through a SecretKeyFactory, which performs 65,536 iterations to slow down the hashing process, thereby proofing security against brute-force attacks. This hash is encoded in Base64 format for easy storage and display. 

The authenticateUser method allows for user authentication by hashing an attempted password with the original salt and comparing it to the stored hash. If they match, the user is authenticated successfully.

The main method provides user interaction, prompting the user to enter and re-enter their password for initial setup and subsequent authentication, sshowcasing the practical application of these security measures in real-world scenarios.
