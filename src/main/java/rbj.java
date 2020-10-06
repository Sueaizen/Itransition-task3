import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Scanner;

public class rbj {
    public static void main(String[] args) {
        if (argsCheck(args)) {
            System.out.println("Bad arguments");
            return;
        }
        String key = toHex(generateStrongAESKey(256).getEncoded());

        int computerChoice = new Random().nextInt(args.length);
        String HMAC = hmacDigest(computerChoice + "", key, "HmacSHA256");

        int yourChoice = checker(args, HMAC);
        if (yourChoice == 0) {
            return;
        }
        System.out.println("Your move: " + args[yourChoice - 1]);
        System.out.println("Computer move: " + args[computerChoice]);
        result(args, computerChoice, yourChoice);
        System.out.println("HMAC key: " + key);
    }

    public static boolean argsCheck(String[] args) {
        if (args.length >= 3 && new HashSet<>(Arrays.asList(args)).size() == args.length && args.length % 2 == 1) {
            return false;
        } else {
            return true;
        }

    }

    public static SecretKey generateStrongAESKey(final int keySize) {
        final KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        final SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        keyGenerator.init(keySize, rng);

        return keyGenerator.generateKey();
    }

    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();

    }

    public static String hmacDigest(String computerChoice, String keyString, String HMAC3) {
        String digest = null;
        try {
            SecretKeySpec key = new SecretKeySpec((keyString).getBytes("UTF-8"), HMAC3);
            Mac mac = Mac.getInstance(HMAC3);
            mac.init(key);

            byte[] bytes = mac.doFinal(computerChoice.getBytes("ASCII"));

            StringBuffer hash = new StringBuffer();
            for (int i = 0; i < bytes.length; i++) {
                String hex = Integer.toHexString(0xFF & bytes[i]);
                if (hex.length() == 1) {
                    hash.append('0');
                }
                hash.append(hex);
            }
            digest = hash.toString();
        } catch (UnsupportedEncodingException e) {
        } catch (InvalidKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        }
        return digest;
    }

    public static void mainMenu(String args[], String HMAC) {
        System.out.println("HMAC= " + HMAC);
        System.out.println("Available moves:");
        for (int i = 0; i < args.length; i++) {
            System.out.println(i + 1 + " - " + args[i]);
        }
        System.out.println(0 + " - exit");
    }

    public static int playerChoice(String[] args) {
        System.out.println("Enter you move:");
        Scanner scanner = new Scanner(System.in);
        int playerChoice = -1;
        if (scanner.hasNextInt()) {
            playerChoice = scanner.nextInt();
            if (playerChoice <= args.length) {
                return playerChoice;
            }
        }
        return -1;

    }

    public static int checker(String[] args, String HMAC) {
        mainMenu(args, HMAC);
        int result = playerChoice(args);
        if (result == -1) {
            result=checker(args, HMAC);

        }
        return result;
    }

    public static int game(String[] args, int comp, int you) {
        if (you == comp) {
            return 0;
        }
        for (int i = 1; i <= args.length / 2; i++) {
            if ((you + i) % args.length == (comp)) {
                return -1;
            }
        }
        return 1;
    }

    public static void result(String[] args, int computerChoice, int yourChoice) {
        switch (game(args, computerChoice, yourChoice - 1)) {
            case (1):
                System.out.println("You win");
                break;
            case (-1):
                System.out.println("You lose");
                break;
            case (0):
                System.out.println("Its a draw");
                break;
        }
    }
}






