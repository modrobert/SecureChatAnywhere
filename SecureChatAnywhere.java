/* 
    SecureChatAnywhere encrypts/decrypts chat messages with AES-128/CBC.
    Copyright (C) 2018  Robert V. <modrobert@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import java.util.Base64;
import java.util.Properties;
import java.util.TreeMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.awt.*;
import java.awt.event.*;
import java.awt.datatransfer.*;

import java.net.*; 
import java.io.*;

/**
 * @author Copyright (C) 2018  Robert V. (modrobert@gmail.com)
 * SecureChatAnywhere encrypts/decrypts chat messages with AES-128/CBC.
 * 
 */

public class SecureChatAnywhere {

    public static final String APP_VERSION =
        "SecureChatAnywhere v0.98 Beta [AES-128/CBC]";
    public static final String MAGIC_ID = "SCA-";
    private static final String KEY_FILE = "SecureChatAnywhere.keys.txt";
    private static final String KEY_WARNING =
        "Think about how you share the keys.";
    private static final String ENC_PASTE_HERE =
        "<type/paste text to encrypt here>";
    public static final String DEC_PASTE_HERE =
        "<paste text to decrypt here>";

    private static final int BASE64_WIDTH = 40;
    private static final int FONT_SIZE_AREA = 11;
    private static final int FONT_SIZE_BUTTON = 12;
    private static final int FONT_SIZE_CHOICE = 11;
    private static final int TEXT_AREA_WIDTH = 45;
    private static final int KEYLABEL_CHAR_LIMIT = 15;

    private static String key;
    private static String[] keysel;
    private static String[] keyname;
    private static int keynum;
    private static String genkey;

    private TextArea output;
    private TextArea encr;
    private TextArea decr;
    private Button encryptButton;
    private Button decryptButton;
    private Button clearButtonDW;
    private Button clearButtonEW;
    private Checkbox copyToClipBox;
    private Choice keys;
    private MenuItem aboutMenuItem;
    private MenuItem encryptMenuItem;
    private MenuItem decryptMenuItem;
    private MenuItem clearMenuItem;
    private MenuItem gkeysMenuItem;
    private MenuItem lkeysMenuItem;
    private MenuItem editkeysMenuItem;
    private MenuItem quitMenuItem;
    private Dialog aboutDialog;
    private Dialog gkeysDialog;
    private Dialog lkeysDialog;
    private TextField hexkeyfield;

    public SecureChatAnywhere() {
        
        output = new TextArea(
            "log window\n", 10, 80, TextArea.SCROLLBARS_VERTICAL_ONLY);
        output.setEditable(false);
        output.setFont(new Font("monospaced", Font.PLAIN, FONT_SIZE_AREA));
        encr = new TextArea(ENC_PASTE_HERE, 10, TEXT_AREA_WIDTH);
        encryptButton = new Button("<<- Encrypt");
        encryptButton.setFont(new Font(
            "monospaced", Font.BOLD, FONT_SIZE_BUTTON));
        encr.setFont(new Font("monospaced", Font.PLAIN, FONT_SIZE_AREA));
        encr.setEditable(true);
        decr = new TextArea(DEC_PASTE_HERE, 10, TEXT_AREA_WIDTH);
        decryptButton = new Button("Decrypt ->>");
        decryptButton.setFont(new Font(
            "monospaced", Font.BOLD, FONT_SIZE_BUTTON));
        decr.setFont(new Font("monospaced", Font.PLAIN, FONT_SIZE_AREA));
        decr.setEditable(true);
        clearButtonDW = new Button("<<- Clear");
        clearButtonDW.setFont(new Font(
            "monospaced", Font.BOLD, FONT_SIZE_BUTTON));
        clearButtonEW = new Button("Clear ->>");
        clearButtonEW.setFont(new Font(
            "monospaced", Font.BOLD, FONT_SIZE_BUTTON));
        keys = new Choice();
        copyToClipBox = new Checkbox("Copy to clipboard");
        copyToClipBox.setState(true);
        keys.setFont(new Font("monospaced", Font.PLAIN, FONT_SIZE_CHOICE));
        encryptMenuItem = new MenuItem("Encrypt");
        decryptMenuItem = new MenuItem("Decrypt");
        clearMenuItem = new MenuItem("Clear");
        gkeysMenuItem = new MenuItem("Generate key");
        lkeysMenuItem = new MenuItem("List keys");
        editkeysMenuItem = new MenuItem("Edit keyfile");
        aboutMenuItem = new MenuItem("About");
        quitMenuItem = new MenuItem("Quit");
    }

    public void launchFrame() throws Exception {
        Frame frame = new Frame(APP_VERSION);

        frame.setLayout(new BorderLayout());
        
        frame.add(encr,BorderLayout.LINE_START);
        frame.add(output,BorderLayout.PAGE_END);
        frame.add(decr,BorderLayout.LINE_END);

        // get keys for selection
        for (int i = 0; i < keynum; i++) {
            keys.add(keyname[i]);
        }

        Panel p1 = new Panel();
        p1.add(encryptButton);
        p1.add(decryptButton);
        p1.add(clearButtonDW);
        p1.add(clearButtonEW);
        p1.add(keys);
        p1.add(copyToClipBox);
        frame.add(p1,BorderLayout.CENTER);
        
        MenuBar mb = new MenuBar();
        Menu menu = new Menu("Action");
        menu.add(encryptMenuItem);
        menu.add(decryptMenuItem);
        menu.add(clearMenuItem);
        menu.addSeparator();
        menu.add(gkeysMenuItem);
        menu.add(lkeysMenuItem);
        menu.add(editkeysMenuItem);
        menu.addSeparator();
        menu.add(quitMenuItem);
        Menu help = new Menu("Help");
        help.add(aboutMenuItem);
        mb.add(menu);
        mb.setHelpMenu(help);
        frame.setMenuBar(mb);

        // create the aboutDialog once, it will be reused later
        aboutDialog = new AboutDialog(frame,"About",true);
        aboutDialog.setResizable(false);

        // create the gkeysDialog once, it will be reused later
        gkeysDialog = new gKeysDialog(frame,"Generate key",true);
        gkeysDialog.setResizable(false);

        // create the lkeysDialog once, it will be reused later
        lkeysDialog = new lKeysDialog(frame,"List keys",true);
        lkeysDialog.setResizable(false);

        // attach listener to the appropriate components
        encr.addMouseListener(new MouseListener() {
            public void mouseClicked(MouseEvent e) {
                // clear out the initial text after mouse click
                if (encr.getText().equals(ENC_PASTE_HERE)) {
                    encr.setText(" ");
                    encr.setText("");
                }
            }
            public void mousePressed(MouseEvent e) {
            }
            public void mouseReleased(MouseEvent e) {
            }
            public void mouseEntered(MouseEvent e) {
            }
            public void mouseExited(MouseEvent e) {
            }
        });
        decr.addMouseListener(new MouseListener() {
            public void mouseClicked(MouseEvent e) {
                // clear out the initial text after mouse click
                if (decr.getText().equals(DEC_PASTE_HERE)) {
                    decr.setText(" ");
                    decr.setText("");
                }
            }
            public void mousePressed(MouseEvent e) {
            }
            public void mouseReleased(MouseEvent e) {
            }
            public void mouseEntered(MouseEvent e) {
            }
            public void mouseExited(MouseEvent e) {
            }
        });
        encryptButton.addActionListener(new EncryptHandler());
        decryptButton.addActionListener(new DecryptHandler());
        clearButtonDW.addActionListener(new ClearHandlerDW());
        clearButtonEW.addActionListener(new ClearHandlerEW());
        copyToClipBox.addItemListener(new copyToClipBoxHandler());
        encryptMenuItem.addActionListener(new EncryptHandler());
        decryptMenuItem.addActionListener(new DecryptHandler());
        clearMenuItem.addActionListener(new ClearHandler());
        frame.addWindowListener(new CloseHandler());
        encr.addFocusListener(new EncryptAHandler());
        decr.addFocusListener(new DecryptAHandler());
        quitMenuItem.addActionListener(new quitHandler());
        aboutMenuItem.addActionListener(new AboutHandler());
        gkeysMenuItem.addActionListener(new gKeysMenuHandler());
        lkeysMenuItem.addActionListener(new lKeysMenuHandler());
        editkeysMenuItem.addActionListener(new editkeysMenuHandler());

        frame.setSize(800,600);
        frame.setResizable(false);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
        output.requestFocus();
    }

    private static String aesEncryptText (String s) throws Exception {
        /* hardcoded AES-128/CBC test vectors from NIST 800-38A
        byte[] keybytes =
            hexStringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = hexStringToByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] byteDataToEncrypt = 
            hexStringToByteArray("6bc1bee22e409f96e93d7e117393172a");
        */

        // private AES-128 key from file (todo and improve)
        byte[] keybytes = hexStringToByteArray(key); 
        // System.out.println("* Key: " + key);
        final int AES_CBC_IV_SIZE = 16;
        String strCipherText = new String();
        // getting the key
        SecretKeySpec secretKey = new SecretKeySpec(keybytes, "AES");
        // AES_BLOCKSIZE is always 128 bytes, divide by 8 to get CBC IV size
        // add the IV bytes in plaintext with the encrypted data
        byte[] iv = new byte[AES_CBC_IV_SIZE];
        // randomize IV bytes
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);
        // select cipher
        // use "AES/CBC/NoPadding" for test vectors
        // PKCS5Padding = PKCS7Padding for AES in java land :/
        Cipher aesCipherForEncryption = Cipher.getInstance(
            "AES/CBC/PKCS5Padding");
        // init
        aesCipherForEncryption.init(
            Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] byteDataToEncrypt = s.getBytes();
        // encrypt
        byte[] byteCipherText = aesCipherForEncryption.doFinal(
            byteDataToEncrypt);
        // System.out.println(byteArrayToHexString(byteCipherText));
        byte[] combinedIvCipher = new byte[byteCipherText.length + iv.length];
        for (int i = 0; i < combinedIvCipher.length; ++i) {
            combinedIvCipher[i] =
                i < iv.length ? iv[i] : byteCipherText[i - iv.length];
        }
        strCipherText = Base64.getEncoder().encodeToString(combinedIvCipher);
        return strCipherText;
    }

    private static String aesDecryptText (String s) throws Exception {
        // private AES 128 key from file (todo and improve)
        byte[] keybytes = hexStringToByteArray(key); 
        // System.out.println("* Key: " + key);
        final int AES_CBC_IV_SIZE = 16;
        String strDecryptedText = new String();
        // base64 decode
        byte[] byteDataDecoded = Base64.getDecoder().decode(s);
        // AES_BLOCKSIZE is always 128 bytes, divide by 8 to get CBC IV size
        byte[] iv = new byte[AES_CBC_IV_SIZE];
        byte[] byteDataToDecrypt = new byte[byteDataDecoded.length -
            AES_CBC_IV_SIZE];
        // lets get the IV bytes out
        for (int i = 0; i < AES_CBC_IV_SIZE; i++) {
            iv[i] = byteDataDecoded[i];
        }
        // and the rest of the bytes to decrypt
        for (int i = AES_CBC_IV_SIZE ; i < byteDataDecoded.length; i++) {
            byteDataToDecrypt[i - AES_CBC_IV_SIZE] = byteDataDecoded[i];
        }
        // getting the key 
        SecretKeySpec secretKey = new SecretKeySpec(keybytes, "AES");
        // select cipher
        // PKCS5Padding = PKCS7Padding for AES in java land :/
        Cipher aesCipherForDecryption = Cipher.getInstance(
            "AES/CBC/PKCS5Padding");
        // init
        aesCipherForDecryption.init(
            Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        // decrypt
        byte[] byteDecryptedText =
            aesCipherForDecryption.doFinal(byteDataToDecrypt);
        strDecryptedText = new String(byteDecryptedText);
        return strDecryptedText;
    }

    private void encryptText() throws Exception {
        String strCipherText = new String();
        String text = encr.getText();
        key = findKey();
        // don't encrypt empty string
        if (text != null && !text.isEmpty()) {
            strCipherText = aesEncryptText(text);
            output.append("---[ encrypted with key: " +
                keys.getSelectedItem() + " ]---" + "\n");
            output.append("Plaintext:\n" + text + "\n");
            String strCipherTextFormatted = insertPeriodically(
                MAGIC_ID + strCipherText, "\n", BASE64_WIDTH);
            decr.setText(" ");
            decr.setText("");
            decr.repaint();
            decr.append(strCipherTextFormatted);
            if (copyToClipBox.getState()) {
                // copy to clipboard
                StringSelection sel =
                    new StringSelection(strCipherTextFormatted);
                Clipboard cb =
                    Toolkit.getDefaultToolkit().getSystemClipboard();
                cb.setContents(sel, sel);
                output.append("Ciphertext (copied to clipboard):\n" +
                    strCipherTextFormatted + "\n");
            } else {
                output.append("Ciphertext:\n" + strCipherTextFormatted + "\n");
            }
            output.setCaretPosition(output.getText().length());
            output.repaint();
        } else {
            output.append("---[ encryption error ]---" + "\n");
            output.append("Empty string." + "\n");
            output.setCaretPosition(output.getText().length());
            output.repaint();
        }
    }

    private void decryptText() throws Exception {
        String decText = new String();
        String encText = new String();
        String allText = decr.getText();
        key = findKey();
        // remove spaces
        allText = allText.replaceAll(" ", "");
        // remove linefeeds
        allText = allText.replaceAll("(?:\\r\\n|\\n\\r|\\n|\\r)", "");
        // only process if encrypted message contains MAGIC_ID
        if (allText.startsWith(MAGIC_ID)) {
            encText = allText.substring(MAGIC_ID.length(), allText.length()); 
            if (IsBase64Encoded(encText)) {
                try {
                    decText = aesDecryptText(encText);
                } catch (Exception e) {
                    // System.out.println("* Decryption error: " + e);
                    output.append("---[ decryption with key: " +
                        keys.getSelectedItem() + " error ]---" + "\n");
                    output.append("Wrong key or corrupt/modified ciphertext." +
                        "\n");
                    return;
                }
                output.append("---[ decrypted with key: " +
                    keys.getSelectedItem() + " ]---" + "\n");
                String encTextFormatted = insertPeriodically(
                    MAGIC_ID + encText, "\n", BASE64_WIDTH);
                output.append("Ciphertext:\n" + encTextFormatted + "\n");
                encr.setText(" ");
                encr.setText("");
                encr.repaint();
                encr.append(decText);
                if (copyToClipBox.getState()) {
                    // copy to clipboard
                    StringSelection sel = new StringSelection(decText);
                    Clipboard cb =
                        Toolkit.getDefaultToolkit().getSystemClipboard();
                    cb.setContents(sel, sel);
                    output.append("Plaintext (copied to clipboard):\n" +
                         decText + "\n");
                } else {
                    output.append("Plaintext:\n" + decText + "\n");
                }
                output.setCaretPosition(output.getText().length());
                output.repaint();

            } else {
                
                output.append("---[ decryption error ]---" + "\n");
                String encTextFormatted = insertPeriodically(
                    MAGIC_ID + encText, "\n", 60);
                output.append("Base64 error in:\n" + encTextFormatted + "\n");
                output.setCaretPosition(output.getText().length());
                output.repaint();
            }
        } else {
            output.append("---[ decryption error ]---" + "\n");
            if (allText != null && !allText.isEmpty()) {
                output.append("Magic ID '" + MAGIC_ID + "' missing." + "\n");
            } else {
                output.append("Empty string." + "\n");
            }
            output.setCaretPosition(output.getText().length());
            output.repaint();
        }
    }

    private class copyToClipBoxHandler implements ItemListener {
        public void itemStateChanged(ItemEvent ie) {
            copyToClipBox.repaint();      
        }
    }

    private class EncryptAHandler implements FocusListener {
        public void focusGained(FocusEvent e) {
        } 
        public void focusLost(FocusEvent e) {
        }
    }

    private class EncryptHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {
                encryptText();
            } catch (Exception exc) {
                System.out.println("* Encryption menu error: " + exc);
            }
        }
    }

    private class DecryptAHandler implements FocusListener {
        public void focusGained(FocusEvent e) {
        }
        public void focusLost(FocusEvent e) {
        }
    }

    private class DecryptHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {
                decryptText();
            } catch (Exception exc) {
                System.out.println("* Decryption menu error: " + exc);
            }
        }
    }

    private class ClearHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            decr.setText(" ");
            decr.setText("");
            encr.setText(" ");
            encr.setText("");
        }
    }

    private class ClearHandlerDW implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            encr.setText(" ");
            encr.setText("");
        }
    }

    private class ClearHandlerEW implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            decr.setText(" ");
            decr.setText("");
        }
    }

    private class CloseHandler extends WindowAdapter {
        public void windowClosing(WindowEvent e) {
            System.exit(0);
        }
    }

    private class AboutHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            aboutDialog.setLocationRelativeTo(clearButtonDW);
            aboutDialog.setVisible(true);
        }
    }

    private class gKeysMenuHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            gkeysDialog.setLocationRelativeTo(clearButtonDW);
            genkey = genHexKey();
            hexkeyfield.setText(genkey);
            gkeysDialog.setVisible(true);
        }
    }

    private class lKeysMenuHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            lkeysDialog.setLocationRelativeTo(clearButtonDW);
            lkeysDialog.setVisible(true);
        }
    }

    private class editkeysMenuHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (Desktop.isDesktopSupported()) {
                File kf = new File(KEY_FILE);
                try {
                    Desktop.getDesktop().open(kf);
                } catch (IOException error) {
                    error.printStackTrace();
                }
            }
        }
    }

    private class AboutCloseHandler extends WindowAdapter {
        public void windowClosing(WindowEvent e) {
            aboutDialog.setVisible(false);
        }
    }

    private class gKeysCloseHandler extends WindowAdapter {
        public void windowClosing(WindowEvent e) {
            gkeysDialog.setVisible(false);
        }
    }

    private class lKeysCloseHandler extends WindowAdapter {
        public void windowClosing(WindowEvent e) {
            lkeysDialog.setVisible(false);
        }
    }

    private class genKeyHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            genkey = genHexKey();
            hexkeyfield.setText(genkey);
        }
    }

    private class AboutDialog extends Dialog implements ActionListener  {
        public AboutDialog(Frame parent, String title, boolean modal) {
            super(parent,title,modal);
            Panel a = new Panel();
            a.setLayout(new GridLayout(0,1));
            a.add(new Label(APP_VERSION));
            a.add(new Label(
                "Copyright (C) 2018  Robert V. <modrobert@gmail.com>"));
            a.add(new Label("Free software licensed under GPLv3."));
            a.add(new Label("Donate Bitcoin: "));
            TextField bitcoin = new TextField(
                "1LdBPjasAMLSBUEMF4w4AGuyPBBTtDZ92H", 34);
            bitcoin.setEditable(false);
            a.add(bitcoin);
            add(a,BorderLayout.CENTER);
            addWindowListener(new AboutCloseHandler());
            Button b = new Button("Close");
            add(b,BorderLayout.PAGE_END);
            pack();
            b.addActionListener(this);
        }
        // closes itself when the close button is pushed
        public void actionPerformed(ActionEvent e) {
            setVisible(false);
        }
    }

    private class gKeysDialog extends Dialog implements ActionListener  {
        public gKeysDialog(Frame parent, String title, boolean modal) {
            super(parent,title,modal);
            Panel k = new Panel();
            k.setLayout(new GridLayout(0,1));
            k.setFont(new Font("monospaced", Font.PLAIN, FONT_SIZE_BUTTON));
            k.add(new Label(KEY_WARNING));
            Label lbl;
            genkey = genHexKey();
            hexkeyfield = new TextField(genkey, 32);
            hexkeyfield.setEditable(false);
            k.add(hexkeyfield);
            addWindowListener(new gKeysCloseHandler());
            Button g = new Button("Generate random key");
            g.addActionListener(new genKeyHandler());
            Button b = new Button("Close");
            k.add(g);
            k.add(b);
            add(k,BorderLayout.CENTER);
            pack();
            b.addActionListener(this);
        }
        // closes itself when the OK button is pushed
        public void actionPerformed(ActionEvent e) {
            setVisible(false);
        }
    }

    private class lKeysDialog extends Dialog implements ActionListener  {
        public lKeysDialog(Frame parent, String title, boolean modal) {
            super(parent,title,modal);
            Panel j = new Panel();
            Panel k = new Panel();
            j.setLayout(new GridLayout(0,1));
            k.setLayout(new GridLayout(0,1));
            j.setFont(new Font("monospaced", Font.PLAIN, FONT_SIZE_BUTTON));
            k.setFont(new Font("monospaced", Font.PLAIN, FONT_SIZE_BUTTON));
            j.add(new Label(" "));
            k.add(new Label(KEY_WARNING));
            Label lbl;
            TextField txt;
            for (int i = 0; i < keynum; i++) {
                lbl = new Label(keyname[i] + "=");
                txt = new TextField(keysel[i], 32);
                txt.setEditable(false);
                j.add(lbl);
                k.add(txt);
            }
            add(j,BorderLayout.LINE_START);
            add(k,BorderLayout.CENTER);
            addWindowListener(new lKeysCloseHandler());
            Button b = new Button("Close");
            add(b,BorderLayout.PAGE_END);
            pack();
            b.addActionListener(this);
        }
        // closes itself when the close button is pushed
        public void actionPerformed(ActionEvent e) {
            setVisible(false);
        }
    }

    private class quitHandler implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            System.exit(0);
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private String findKey() {
        String s = new String();
        s = keys.getSelectedItem();
        int i;
        for (i = 0; i < keynum; i++) {
            if (s.equals(keyname[i])) {
                break;
            }
        }
        return keysel[i];
    }

    private static String genHexKey() {
        // generate AES-128 key
        KeyGenerator kg = null;
        try {
            kg = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();    
        }
        kg.init(128); // AES-128
        SecretKey key = kg.generateKey();
        String hexkey = byteArrayToHexString(key.getEncoded());
        return hexkey;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static Boolean IsBase64Encoded(String str) {
        String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(str);
        if (m.find()) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean isNumeric(String s) {
        if ( s.length() == 0 || 
            (s.charAt(0) != '-' && Character.digit(s.charAt(0), 16) == -1))
            return false;
        if ( s.length() == 1 && s.charAt(0) == '-' )
            return false;
        for ( int i = 1 ; i < s.length() ; i++ )
            if ( Character.digit(s.charAt(i), 16) == -1 )
                return false;
        return true;
    }

    public static boolean isWindows() {
        return System.getProperty("os.name").startsWith("Windows");
    }

    public static void waitKeyWindows() {
        if (isWindows()) {
            System.out.println("Press ENTER to continue.");
            try {
                int foo = System.in.read();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static String insertPeriodically(
        String text, String insert, int period)
    {
        StringBuilder builder = new StringBuilder(
            text.length() + insert.length() * (text.length()/period)+1);

        int index = 0;
        String prefix = "";
        while (index < text.length())
        {
            builder.append(prefix);
            prefix = insert;
            builder.append(text.substring(index, 
                Math.min(index + period, text.length())));
            index += period;
        }
        return builder.toString();
    }

    public static void main(String[] args) throws Exception {
        String opt = System.getProperty("file.encoding");
        if (!opt.equalsIgnoreCase("utf-8"))
        {
            System.out.println(
                "* Start with java option: -Dfile.encoding=UTF-8 ");
            waitKeyWindows();
            System.exit(1);
        }
        Properties prop = new Properties();
        PrintWriter writer = null;
        System.out.println("* Reading key file: " + KEY_FILE);
        try {
            prop.load(new FileInputStream(KEY_FILE));
        } catch (IOException e) {
            System.out.println("* Key file not found.");
            System.out.println("* Creating " + KEY_FILE +
                " and generating AES-128 keys.");
            try {
                writer = new PrintWriter(KEY_FILE, "UTF-8");
            } catch (IOException e2) {
                e2.printStackTrace();
                waitKeyWindows();
                System.exit(1);
            }
            // generate AES-128 keys
            writer.println("# " + KEY_WARNING);
            writer.println("key01=" + genHexKey());
            writer.println("key02=" + genHexKey());
            writer.println("key03=" + genHexKey());
            writer.close();
            System.out.println("* Reading key file: " + KEY_FILE);
            try {
                 prop.load(new FileInputStream(KEY_FILE));
            } catch (IOException e3) {
                e3.printStackTrace();
                waitKeyWindows();
                System.exit(1);
            }        
        }
        int i = 0;
        Map<String,String> propmap = new TreeMap<String,String>();
        for (Map.Entry<Object, Object> row : prop.entrySet()) {
            String lbl = (String) row.getKey();
            int len = lbl.length();
            if (len > KEYLABEL_CHAR_LIMIT) {
                 System.out.println("* Key label '" + row.getKey() + 
                    "' is too long, keep it under " + KEYLABEL_CHAR_LIMIT +
                    " chars.");                
                waitKeyWindows();
                System.exit(1);
            }
            propmap.put((String) row.getKey(), (String) row.getValue());
            i++;
        }
        // System.out.println("propmap values: " + propmap);
        // System.out.println("prop values: " + prop);
        keyname = new String[i];
        keysel = new String[i];
        keynum = 0;
        for (Map.Entry<String, String> row : propmap.entrySet()) {
            keyname[keynum] = row.getKey();
            keysel[keynum] = row.getValue();
            if (keysel[keynum].length() != 32) {
                System.out.println("* Invalid key length for '" +
                    keyname[keynum] + "', need 32 hex chars (128 bit).");
                waitKeyWindows();
                System.exit(1);
            }
            if (isNumeric(keysel[keynum]) == false) {
                System.out.println("* Key '" + keyname[keynum] +
                    "' is not in hexadecimal format.");
                waitKeyWindows();
                System.exit(1);
            }
            keynum++;
        }
        System.out.println("* Starting GUI...");
        SecureChatAnywhere c = new SecureChatAnywhere();
        c.launchFrame();
    }
}

