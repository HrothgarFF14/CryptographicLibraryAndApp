import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        //TIP Press <shortcut actionId="ShowIntentionActions"/> with your caret at the highlighted text
        // to see how IntelliJ IDEA suggests fixing it.
        System.out.printf("Hello and welcome!");
        System.out.println("Hello and welcome!");

        for (int i = 1; i <= 5; i++) {
            //TIP Press <shortcut actionId="Debug"/> to start debugging your code. We have set one <icon src="AllIcons.Debugger.Db_set_breakpoint"/> breakpoint
            // for you, but you can always add more by pressing <shortcut actionId="ToggleLineBreakpoint"/>.
            System.out.println("i = " + i);
        }
        if (args.length < 3) {
            System.out.println("Please provide the input file, output file and password as arguments.");
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];
        String password = args[2];

        KMACXOF256 kmacxof256 = new KMACXOF256();

        // Data provided
        byte[] X = {0x00, 0x01, 0x02, 0x03};
        int L = 256;
        String N = "";
        String S = "Email Signature";

        // Call cSHAKE256 method
        kmacxof256.cSHAKE256(X, L, N, S);

        // Print the output
        byte[] output = kmacxof256.finalHash();
        System.out.println(Arrays.toString(output));

        // Write the output to the outputFile
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(output);
        } catch (IOException e) {
            System.out.println("Error writing to file: " + e.getMessage());
        }
        // Use inputFile, outputFile and password as needed
    }
}