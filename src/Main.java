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
        //TIP Press <shortcut actionId="ShowIntentionActions"/> with your caret at the highlighted text
        // to see how IntelliJ IDEA suggests fixing it.
        System.out.println("Cryptogtraphy Application by Louis Lomboy, Ahmed Mohamed and Shu-Ren Shen");

        System.out.println("Enter mode of operation: " +
                "\n1-Hash \n2-MAC \n3-Symmetric Encryption \n4-Symmetric Decryption");
        String mode = scanner.nextLine();

        System.out.println("Enter input method: \n1-File Input \n2-Console Input");
        String inputMethod = scanner.nextLine();

        System.out.println("Enter output method: \n1-File Output \n2-Console Output");
        String outputMethod = scanner.nextLine();

        switch (mode) {
            case "1":
                // Hash
                byte[] data = getData(inputMethod);
                byte[] hash = hashData(data);
                outputData(hash, outputMethod);
                break;
            case "2":
                // MAC
                break;
            case "3":
                // Symmetric Encryption
                break;
            case "4":
                // Symmetric Decryption
                break;
            default:
                System.out.println("Invalid mode selected.");
                break;
        }

        scanner.close();
        System.out.println("---Done!---");
    }

    private static byte[] getData(String inputMethod) {
        if ("1".equals(inputMethod)) {
            System.out.println("Enter file path:");
            String filePath = scanner.nextLine();
            try {
                return Files.readAllBytes(Paths.get(filePath));
            } catch (IOException e) {
                System.out.println("Error reading file: " + e.getMessage());
            }
        } else if ("2".equals(inputMethod)) {
            System.out.println("Enter data:");
            String data = scanner.nextLine();
            return data.getBytes();
        }
        return new byte[0];
    }

    private static byte[] hashData(byte[] data) {
        KMACXOF256 kmacxof256 = new KMACXOF256();
        kmacxof256.KMACXOF256(data, 256);
        return kmacxof256.finalHash();
    }

    private static void outputData(byte[] data, String outputMethod) {
        if ("1".equals(outputMethod)) {
            System.out.println("Enter output file path:");
            String filePath = scanner.nextLine();
            try (FileOutputStream fos = new FileOutputStream(filePath)) {
                fos.write(data);
            } catch (IOException e) {
                System.out.println("Error writing to file: " + e.getMessage());
            }
        } else if ("2".equals(outputMethod)) {
            for (byte b : data) {
                System.out.print(String.format("%02X ", b));
            }
            System.out.println();
        }
    }
}