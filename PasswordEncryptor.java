import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class PasswordEncryptor {

    // Method to generate salt
    public static byte[] generateSalt() {
        // Code will go here
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // A different size may be choosen
        random.nextBytes(salt);
        return salt;
    }

    // Method to encrypt password
    public static String encryptPassword(String password, byte[] salt) {
        // Code will go here
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128); // 65536 iterations, 128-bit key
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    // Method to authenticate user
    public static boolean authenticateUser(String attemptedPassword, String encryptedPassword, byte[] salt) {
        // Code will go here
        // Encrypt the attempted password using the original salt
        String attemptedPasswordEncrypted = encryptPassword(attemptedPassword, salt);
        // Compare the encrypted attempted password with the original encrypted password
        return attemptedPasswordEncrypted.equals(encryptedPassword);
    }

    // Main method to run the program
    public static void main(String[] args) {
        // User interaction code will go here
        @SuppressWarnings("resource")
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter your password: ");
        String password = scanner.nextLine();

        // Generate salt and encrypt the password
        byte[] salt = generateSalt();
        String encryptedPassword = encryptPassword(password, salt);

        System.out.println("Your encrypted password is: " + encryptedPassword);
        System.out.println("Salt (Base64 encoded): " + Base64.getEncoder().encodeToString(salt));

        // Authentication process
        System.out.print("Enter your password again for login: ");
        String loginPassword = scanner.nextLine();
        boolean isAuthenticated = authenticateUser(loginPassword, encryptedPassword, salt);

        if (isAuthenticated) {
            System.out.println("User authenticated successfully.");
        } else {
            System.out.println("Authentication failed.");
        }
    }
}
