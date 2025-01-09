import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSAPrototype {

    // RSA Key Generator
    static class RSAKeyGenerator {
        private BigInteger p;
        private BigInteger q;
        private BigInteger n;
        private BigInteger phi;
        private BigInteger e;
        private BigInteger d;
        private int bitLength = 512;

        // Generates a secure RSA key pair using large random primes.
        public void generateKeys() {
            SecureRandom random = new SecureRandom();

            // Generate two distinct large primes
            p = BigInteger.probablePrime(bitLength, random);
            do {
                q = BigInteger.probablePrime(bitLength, random);
            } while (q.equals(p));

            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // Common choice for e
            e = BigInteger.valueOf(65537);

            if (!phi.gcd(e).equals(BigInteger.ONE)) {
                // If not coprime, pick another small odd integer
                e = BigInteger.valueOf(3);
                while (phi.gcd(e).intValue() > 1) {
                    e = e.add(BigInteger.TWO);
                }
            }

            // Compute d
            d = e.modInverse(phi);

            System.out.println("\n=== Secure RSA (Large Primes) ===");
            System.out.println("Public Key (e, n):");
            System.out.println("  e = " + e);
            System.out.println("  n = " + n);
            System.out.println("Private Key d    = " + d);
        }

        // Demonstrates an "insecure" setup (small primes).
        public void setInsecureKeys(BigInteger p, BigInteger q) {
            this.p = p;
            this.q = q;
            this.n = p.multiply(q);
            this.phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // Pick a random e that is coprime with phi(n).
            SecureRandom random = new SecureRandom();
            do {
                // Generate a random e in the range (1, phi).
                // We ensure e > 1 and < phi, and gcd(e, phi) = 1
                e = new BigInteger(phi.bitLength(), random);
            } while ( e.compareTo(BigInteger.ONE) <= 0
                   || e.compareTo(phi) >= 0
                   || !phi.gcd(e).equals(BigInteger.ONE) );

            d = e.modInverse(phi);
        }

        public BigInteger getPublicKeyE() {
            return e;
        }

        public BigInteger getPublicKeyN() {
            return n;
        }

        public BigInteger getPrivateKeyD() {
            return d;
        }
    }

    // RSA (encrypt/decrypt)
    static class RSA {
        private final BigInteger e;
        private final BigInteger d;
        private final BigInteger n;

        public RSA(BigInteger e, BigInteger d, BigInteger n) {
            this.e = e;
            this.d = d;
            this.n = n;
        }

        public BigInteger encrypt(BigInteger message) {
            return message.modPow(e, n);
        }

        public BigInteger decrypt(BigInteger ciphertext) {
            return ciphertext.modPow(d, n);
        }
    }

    // Utility: check primality
    private static boolean isPrime(BigInteger x) {
        // For demonstration, the built-in isProbablePrime(100) is typically enough
        return x.isProbablePrime(100);
    }

    // Main Simulation
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        RSAKeyGenerator keyGen = new RSAKeyGenerator();

        // Generate Secure RSA 
        keyGen.generateKeys();
        RSA secureRSA = new RSA(keyGen.getPublicKeyE(), 
                                keyGen.getPrivateKeyD(), 
                                keyGen.getPublicKeyN());

        // Demonstrate encryption/decryption with large primes
        System.out.println("\n=== Secure Communication ===");
        System.out.print("Alice, enter a message (integer): ");
        String input = scanner.nextLine();
        BigInteger message;
        try {
            message = new BigInteger(input);
        } catch (NumberFormatException ex) {
            System.out.println("Invalid integer. Exiting.");
            scanner.close();
            return;
        }

        // Alice encrypts
        BigInteger secureCipher = secureRSA.encrypt(message);
        System.out.println("Alice sends ciphertext: " + secureCipher);

        // Charlie intercepts
        System.out.println("Charlie intercepts: " + secureCipher);

        // Bob decrypts
        BigInteger secureDecrypted = secureRSA.decrypt(secureCipher);
        System.out.println("Bob decrypts: " + secureDecrypted);

        //Insecure Scenario in a loop
        System.out.println("\n=== Insecure Scenario ===");
        System.out.println("(Type 'exit' at any prompt to quit.)");

        while (true) {
            // Prompt for p
            System.out.print("\nEnter small prime p (ideally under 50) (or 'exit'): ");
            String pInput = scanner.nextLine();
            if ("exit".equalsIgnoreCase(pInput)) {
                System.out.println("Exiting insecure scenario...");
                break;
            }

            // Prompt for q
            System.out.print("Enter small prime q (ideally under 50) (or 'exit'): ");
            String qInput = scanner.nextLine();
            if ("exit".equalsIgnoreCase(qInput)) {
                System.out.println("Exiting insecure scenario...");
                break;
            }

            // Convert to BigInteger
            BigInteger p, q;
            try {
                p = new BigInteger(pInput);
                q = new BigInteger(qInput);
            } catch (NumberFormatException ex) {
                System.out.println("[ERROR] Invalid integer input. Please try again.");
                continue;  // go back to top of while-loop
            }

            // Build the insecure keys
            keyGen.setInsecureKeys(p, q);

            // Print out the public/private keys (even if p or q is not prime)
            BigInteger e = keyGen.getPublicKeyE();
            BigInteger n = keyGen.getPublicKeyN();
            BigInteger d = keyGen.getPrivateKeyD();

            System.out.println("\nInsecure Public Key: (e=" + e + ", n=" + n + ")");
            System.out.println("Insecure Private Key: d=" + d);

            // Prompt for the message
            System.out.print("\nAlice, enter a message to encrypt (or 'exit'): ");
            String msgInput = scanner.nextLine();
            if ("exit".equalsIgnoreCase(msgInput)) {
                System.out.println("Exiting insecure scenario...");
                break;
            }

            // Convert to BigInteger
            BigInteger insecureMsg;
            try {
                insecureMsg = new BigInteger(msgInput);
            } catch (NumberFormatException ex) {
                System.out.println("[ERROR] Invalid integer input. Please try again.");
                continue;  // loop again
            }

            // Encrypt the message
            RSA insecureRSA = new RSA(e, d, n);
            BigInteger insecureCipher = insecureRSA.encrypt(insecureMsg);

            // Print ciphertext
            System.out.println("Alice sends insecure ciphertext: " + insecureCipher);
            System.out.println("Charlie intercepts: " + insecureCipher);

            BigInteger bobDecrypted = insecureRSA.decrypt(insecureCipher);
            System.out.println("Bob decrypts ciphertext: " + bobDecrypted);

            // Compare bobDecrypted with insecureMsg to see if they're the same
            boolean matchesOriginal = bobDecrypted.equals(insecureMsg);

            // Check #1: Are p and q truly prime? 
            if (!isPrime(p) || !isPrime(q)) {
                // Show that it doesn't decrypt properly
                System.out.println("\n[WARNING] p or q isn't prime => This might break RSA math.");
                System.out.println("[INFO] Original Message:  " + insecureMsg);
                System.out.println("[INFO] Decrypted Message: " + bobDecrypted);
                if (!matchesOriginal) {
                    System.out.println("[RESULT] Decryption differs from the original. RSA is invalid here!");
                }
                continue; // loop again
            }

            // Check #2: Is message >= n?
            if (insecureMsg.compareTo(n) >= 0) {
                System.out.println("\n[WARNING] Message >= n => You won't get the original message back.");
                System.out.println("[INFO] Original Message:  " + insecureMsg);
                System.out.println("[INFO] Decrypted Message: " + bobDecrypted);
                if (!matchesOriginal) {
                    System.out.println("[RESULT] Decryption differs from the original. This is expected because m >= n.");
                }
                continue; // loop again
            }

            // If we get here, p & q are prime and message < n
            // => should decrypt correctly in normal RSA
            System.out.println("\n[INFO] Original Message:  " + insecureMsg);
            System.out.println("[INFO] Decrypted by Bob:  " + bobDecrypted);
            if (matchesOriginal) {
                System.out.println("[RESULT] Message decrypted correctly!");
            } else {
                System.out.println("[RESULT] Decryption differs from the original? Unexpected for valid RSA!");
            }

            // Demonstrate Charlie's perspective
            System.out.println("\nAssuming Charlie knows p and q ");
            // Recompute phi(n) from p and q
            BigInteger charliePhi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

            BigInteger charlieE = e;

            BigInteger charlieD = charlieE.modInverse(charliePhi);

            // Now Charlie can decrypt the same ciphertext as Bob
            BigInteger charlieDecrypted = insecureCipher.modPow(charlieD, n);

            System.out.println("[Charlie] p=" + p + ", q=" + q);
            System.out.println("[Charlie] n = p*q => " + n);
            System.out.println("[Charlie] phi(n) => " + charliePhi);
            System.out.println("[Charlie] e => " + charlieE);
            System.out.println("[Charlie] d => " + charlieD);
            System.out.println("[Charlie] decrypted => " + charlieDecrypted);

            // Loop again to allow new p, q, or exit
        }

        scanner.close();
        System.out.println("Done.");
    }
}
