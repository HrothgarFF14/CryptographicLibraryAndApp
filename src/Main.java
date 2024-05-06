import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

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

        kmacxof256.cSHAKE256(X, L, N, S);

        byte[] output = kmacxof256.finalHash();
        System.out.println(Arrays.toString(output));

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(output);
        }
    }
}