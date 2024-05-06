import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Scanner;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    private static final Scanner scanner = new Scanner(System.in);
    public static void main(String[] args) {
        // Check if the correct number of arguments are provided
        if (args.length < 3) {
            System.out.println("Please provide the input file, output file, and password as command-line arguments.");
            return;
        }

        // Retrieve the arguments
        String inputFile = args[0];
        String outputFile = args[1];
        String password = args[2];

        String exit = "";
        while (!"exit".equalsIgnoreCase(exit)) {
            System.out.println("Cryptogtraphy Application by Louis Lomboy, Ahmed Mohamed and Shu-Ren Shen");

            String mode = getInput("Enter mode of operation: \n1-Hash \n2-MAC \n3-Symmetric Encryption \n4-Symmetric Decryption");
            byte[] data = getData(inputFile);
            String passphrase = null;
            if ("2".equals(mode) || "3".equals(mode) || "4".equals(mode)) {
                passphrase = getInput("Enter passphrase:");
            }
            switch (mode) {
                case "1":
                    outputData(hashKMAC(data), outputFile);
                    break;
                case "2":
                    outputData(macKMAC(passphrase.getBytes(), data), outputFile);
                    break;
                case "3":
                    symmetricEncryption(passphrase.getBytes(), data, outputFile);
                    break;
                case "4":
                    // Symmetric Decryption
                    break;
                default:
                    System.out.println("Invalid mode selected.");
                    break;
            }
            System.out.println("*** Program Terminated ***");
            exit = getInput("Enter 'exit' to terminate the program or press any key to continue.");
        }

    }

    private static String getInput(String prompt) {
        System.out.println(prompt);
        return scanner.nextLine();
    }

    private static byte[] getData(String inputFile) {
        try {
            return Files.readAllBytes(Paths.get(inputFile));
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            return new byte[0];
        }
    }

    private static String readFile(String filePath) {
        try {
            return new String(Files.readAllBytes(Paths.get(filePath)));
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            return "";
        }
    }

    private static byte[] hashKMAC(byte[] data) {
        KMACXOF256 kmacxof256 = new KMACXOF256();
        kmacxof256.cSHAKE256(data, 512, "", "Email Signature");
        kmacxof256.update(data);
        return kmacxof256.finalHash();
    }

    private static byte[] macKMAC(byte[] key, byte[] data) {
        KMACXOF256 kmacxof256 = new KMACXOF256();
        kmacxof256.cSHAKE256(key, 512, "", "Email Signature");
        kmacxof256.update(data);
        return kmacxof256.finalHash();
    }

    private static void symmetricEncryption(byte[] key, byte[] data, String outputChoice) {
        // TODO: Implement symmetric encryption here
    }

    private static byte[] symmetricDecryption(byte[] iv, byte[] key, byte[] c, byte[] t) {
        // TODO: Implement symmetric decryption here
        return new byte[0];
    }
    private static void outputData(byte[] data, String outputFile) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : data) {
            String hex = Integer.toHexString(0xFF & b).toUpperCase();
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
            hexString.append(' ');
        }
        System.out.println("Output: " + hexString);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(hexString.toString().getBytes());
            System.out.println("Data written to " + outputFile);
        } catch (IOException e) {
            System.out.println("Error writing to file: " + e.getMessage());
        }
    }
}