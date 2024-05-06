import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Scanner;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws IOException {
//        //TIP Press <shortcut actionId="ShowIntentionActions"/> with your caret at the highlighted text
//        // to see how IntelliJ IDEA suggests fixing it.
//        System.out.println("Hello and welcome!");
//
//        for (int i = 1; i <= 5; i++) {
//            //TIP Press <shortcut actionId="Debug"/> to start debugging your code. We have set one <icon src="AllIcons.Debugger.Db_set_breakpoint"/> breakpoint
//            // for you, but you can always add more by pressing <shortcut actionId="ToggleLineBreakpoint"/>.
//            System.out.println("i = " + i);
//        }
        System.out.println("Hello and welcome!");

        if (args.length < 3) {
            System.out.println("Please provide an input file, an output file, and a password.");
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];
        String password = args[2];

        //Read the contents of the input file
        byte[] X = Files.readAllBytes(Paths.get(inputFile));

        KMACXOF256 kmacxof256 = new KMACXOF256();

        int L = 256;
        String N = "";
        String S = password;

        //Compute a plain cryptographic hash of a given file
        kmacxof256.cSHAKE256(X, L, N, S);
        byte[] hash = kmacxof256.finalHash();
        System.out.println("Hash: " + Arrays.toString(hash));

        //Compute a plain cryptographic hash of user input
        System.out.println("Enter text to compute its hash:");
        Scanner scanner = new Scanner(System.in);
        String userInput = scanner.nextLine();
        kmacxof256.cSHAKE256(userInput.getBytes(), L, N, S);
        byte[] userHash = kmacxof256.finalHash();
        System.out.println("User input hash: " + Arrays.toString(userHash));

        //Compute an authentication tag (MAC) of a given file under a given passphrase
        kmacxof256.cSHAKE256(X, L, N, S);
        byte[] mac = kmacxof256.finalHash();
        System.out.println("MAC: " + Arrays.toString(mac));

        //Compute an authentication tag (MAC) of user input under a given passphrase
        System.out.println("Enter text to compute its MAC:");
        String userMacInput = scanner.nextLine();
        kmacxof256.cSHAKE256(userMacInput.getBytes(), L, N, S);
        byte[] userMac = kmacxof256.finalHash();
        System.out.println("User input MAC: " + Arrays.toString(userMac));

        // Encrypt a given data file symmetrically under a given passphrase
        byte[] z = new byte[64]; // Random 512-bit key
        new java.security.SecureRandom().nextBytes(z);
        kmacxof256.cSHAKE256(z, L, N, S);
        byte[] encrypted = kmacxof256.finalHash();
        System.out.println("Encrypted: " + Arrays.toString(encrypted));

        // Decrypt a given symmetric cryptogram under a given passphrase
        kmacxof256.cSHAKE256(encrypted, L, N, S);
        byte[] decrypted = kmacxof256.finalHash();
        System.out.println("Decrypted: " + Arrays.toString(decrypted));

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(hash);
            fos.write(userHash);
            fos.write(mac);
            fos.write(userMac);
            fos.write(encrypted);
            fos.write(decrypted);
        }
    }

}