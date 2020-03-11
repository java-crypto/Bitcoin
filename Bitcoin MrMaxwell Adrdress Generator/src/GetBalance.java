
// source: https://bitcointalk.org/index.php?topic=736607.0

// modifiziert funktioniert

import java.io.*;
import java.net.URL;
import java.net.URLConnection;

public class GetBalance {

    public static void retrieveData(String address, String privateKey, String number, String comment) throws IOException {
        URL bc_api = new URL("https://blockchain.info/q/addressbalance/" + address);
        URLConnection yc = bc_api.openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(yc.getInputStream()));
        String inputLine;
        double btc = 0;
        while ((inputLine = in.readLine()) != null) {
            btc = (Double.parseDouble(inputLine) / 100000000);
            System.out.println("Balance of " + address + " is " + btc + " BTC");
        }
        writeDataToFile(address, Double.toString(btc), privateKey, number, comment);
    }

    // schreibt eine datenzeile
    public static void writeDataToFile(String address, String balance, String privateKey, String number, String comment) throws IOException {
        File file = new File("out2.txt");
        if (!file.exists()) {
            createOutputFile(file);
        }
        FileWriter fw = new FileWriter(file.getAbsoluteFile(), true);
        BufferedWriter out = new BufferedWriter(fw);
        out.write(address + "|" + balance + "|" + privateKey + "|" + number + "|" + comment);
        out.newLine();
        out.close();
    }

    private static void createOutputFile(File file) throws IOException {
        file.createNewFile();
        FileWriter fw = new FileWriter(file.getAbsoluteFile(), false);
        BufferedWriter out = new BufferedWriter(fw);
        out.write("---------- BTC address ----------| : Balance in BTC (Satoshi) | PrivateKey            | Number  | Comment");
        out.newLine();
        out.close();
    }

}
