package ro.ase.epayments;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

public class Main {

    public static byte[] readFromFile(final String path) {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(path))) {
            return inputStream.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException("can't read file");
        }
    }

    public static void main(String[] args) {
        final var originalText = readFromFile("test.docx");

        var simulator = new JavaCardSimulator();

        final var ciphertext = simulator.encrypt(originalText);

        final var plaintext = simulator.decrypt(ciphertext);
        
        System.out.println("Equal after decryption: " + Arrays.equals(originalText, plaintext));
    }
}
