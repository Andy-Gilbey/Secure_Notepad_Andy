package notepad;

import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.print.PageFormat;
import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.awt.print.PrinterJob;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.WindowConstants;
import java.security.SecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SecureNotepad extends JFrame {

    // Serial Versions
    private static final long serialVersionUID = -4003533859600149599L;

    // Variable Declaration
    private JMenuBar menuBarKing;
    private JMenu menuFile;
    private JMenu menuInfo;
    private JMenuItem menuInfoDetails;
    private JMenuItem menuItemExit;
    private JMenuItem menuItemFile;
    private JMenuItem menuItemOpen;
    private JMenuItem menuItemPrint;
    private JMenuItem menuItemSave;
    private JCheckBoxMenuItem menuItemWordWrap;
    private JMenu menuView;
    private JScrollPane scrollBar;
    private JPopupMenu.Separator seperatorA;
    private JPopupMenu.Separator seperatorB;
    private JTextArea textBody;
    File theFileName = null;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Constructor
    public SecureNotepad() {
        initalise();
    }
    
    // JFrame builder method
    private void initalise() {
    	
    	// Give it a more "Windows" look
    	try {
    	    UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
    	} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException e) {
    	    e.printStackTrace();
    	}
    	
    	// Object initalise
        scrollBar = new JScrollPane();
        textBody = new JTextArea();
        menuBarKing = new JMenuBar();
        menuFile = new JMenu();
        menuItemFile = new JMenuItem();
        menuItemOpen = new JMenuItem();
        menuItemSave = new JMenuItem();
        seperatorA = new JPopupMenu.Separator();
        menuItemPrint = new JMenuItem();
        seperatorB = new JPopupMenu.Separator();
        menuItemExit = new JMenuItem();
        menuView = new JMenu();
        menuItemWordWrap = new JCheckBoxMenuItem();
        menuInfo = new JMenu();
        menuInfoDetails = new JMenuItem();
        

        // Dimensions 
        Dimension defaultSize = new Dimension(800, 600);
        Dimension minSize = new Dimension(0, 0);

        try {
            ImageIcon icon = new ImageIcon(SecureNotepad.class.getResource("icon.png"));
            setIconImage(icon.getImage());
        } catch (NullPointerException all) {
            System.out.println("Icon Not Found");
            setIconImage(null);
        }

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE); // Exit on close

        // Initial title
        setTitle("Secure Notepad - Untitled.txt");

        // Set minimum Size and default sizes
        setMinimumSize(minSize);
        setSize(defaultSize);
        setPreferredSize(defaultSize);

        setLocationRelativeTo(null); // Center to screen
        textBody.setColumns(20);
        textBody.setRows(5);
        textBody.setCursor(new Cursor(Cursor.TEXT_CURSOR));
        textBody.setPreferredSize(new Dimension(300, 300));
        textBody.setLineWrap(true);
        scrollBar.setViewportView(textBody);

        getContentPane().add(scrollBar, BorderLayout.CENTER);

        menuFile.setText("File");

        menuItemFile.setText("New");

        menuItemFile.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                menuItemFileActionPerformed(event);
            }
        });
        menuFile.add(menuItemFile);

        menuItemOpen.setText("Open");
        menuFile.add(menuItemOpen);
        menuItemOpen.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                try {
					menuItemOpenActionPerformed(event);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
        });

        menuItemSave.setText("Save");
        menuFile.add(menuItemSave);
        menuItemSave.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                menuItemSaveActionPerformed(event);
            }
        });
        menuFile.add(seperatorA);

        menuItemPrint.setText("Print");
        menuItemPrint.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                menuItemPrintActionPerformed(event);
            }
        });
        menuFile.add(menuItemPrint);
        menuFile.add(seperatorB);

        menuItemExit.setText("Exit");
        menuItemExit.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                menuItemExitActionPerformed(event);
            }
        });
        menuFile.add(menuItemExit);

        menuBarKing.add(menuFile);

        menuView.setText("View");

        menuItemWordWrap.setSelected(true);
        menuItemWordWrap.setText("Wordwrap");
        menuItemWordWrap.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                menuItemWordWrapActionPerformed(evt);
            }
        });
        menuView.add(menuItemWordWrap);

        menuBarKing.add(menuView);

        menuInfo.setText("Info");
        menuInfo.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                menuInfoActionPerformed(event);
            }
        });

        menuInfoDetails.setText("Student Details");
        menuInfoDetails.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                menuInfoDetailsActionPerformed(event);
            }
        });
        menuInfo.add(menuInfoDetails);

        menuBarKing.add(menuInfo);

        setJMenuBar(menuBarKing);

        pack();
    }

    protected void menuItemWordWrapActionPerformed(ActionEvent evt) {
        if (menuItemWordWrap.getState()) {
            menuItemWordWrap.setState(true);
            textBody.setLineWrap(true);
        } else {
            menuItemWordWrap.setState(false);
            textBody.setLineWrap(false);
        }
    }

    protected void menuItemExitActionPerformed(ActionEvent event) {
        System.exit(0);
    }

    protected void menuItemSaveActionPerformed(ActionEvent event) {
        // Create a new JFileChooser object
        JFileChooser fileSelect = new JFileChooser();
        
        // Check if the "Save" action was performed
        if (event.getActionCommand().equals("Save")) {
            
            // If a file has already been opened, set the current directory and selected file to that file
            if (theFileName != null) {
                fileSelect.setCurrentDirectory(theFileName);
                fileSelect.setSelectedFile(theFileName);
            } else {
                // If no file has been opened, set the default selected file to "Untitled.txt"
                fileSelect.setSelectedFile(new File("Untitled.txt"));
            }

            // Display the save dialog box
            int ret = fileSelect.showSaveDialog(null);

            // If the user selects a file and clicks "Save"
            if (ret == JFileChooser.APPROVE_OPTION) {
                try {
                    // Get the selected file
                    File file = fileSelect.getSelectedFile();
                    
                    // Get the text to be saved
                    String textToSave = textBody.getText();
                    
                    // Prompt the user to enter a password for encryption
                    String password = JOptionPane.showInputDialog("Enter Password");

                    // Encrypt the text with the given password
                    byte[] encryptedText = encryptText(textToSave, password);

                    // Save the encrypted text to the file
                    SaveFile(file.getAbsolutePath(), encryptedText);

                    // Set the title of the program to the name of the saved file
                    this.setTitle(file.getName() + " - Notepad");
                    
                    // Set theFileName to the saved file for future use
                    theFileName = file;
                } catch (Exception e) {
                    // Print the stack trace if there's an error
                    e.printStackTrace();
                }
            }
        }
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private void SaveFile(String filename, byte[] encryptedText) throws IOException {
        setCursor(new Cursor(Cursor.WAIT_CURSOR));
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(encryptedText);
        fos.close();
        setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
    }

    protected void menuItemOpenActionPerformed(ActionEvent event) throws Exception {
        JFileChooser fileSelect = new JFileChooser();
        if (event.getActionCommand().equals("Open")) {
            //open
            int num = fileSelect.showDialog(null, "Open");

            if (num == JFileChooser.APPROVE_OPTION) {
                try {
                    File theFile = fileSelect.getSelectedFile();
                    OpenFile(theFile.getAbsolutePath());
                    this.setTitle(theFile.getName() + " - Secure Notepad");
                    theFileName = theFile;
                } catch (IOException e) {
                    System.out.println("Error Occured - Input/Output Exception");
                }
            }
        }
    }
    
    public void OpenFile(String filename) throws Exception {
        // Prompt the user for the password to decrypt the file
        String password = JOptionPane.showInputDialog("Enter Password");

        // Read the encrypted file data into a byte array
        byte[] encryptedData = Files.readAllBytes(Paths.get(filename));

        // If the user didn't enter a password, or entered an empty or blank password,
        // try to crack the password using a list of common passwords
        if(password == null || password.isEmpty() || password.isBlank()) {
            String[] list = new String[1000];
            String input = "";
            list = buildList();

            // Loop through the list of passwords and try to decrypt the file with each one
            attack:  for (int i = 0; i < list.length; i++) {
                input = list[i];
                byte[] decryptedData = decryptData(input, encryptedData);
                String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);

                // If the decrypted text contains non-ASCII characters, the decryption was unsuccessful
                // and we need to try the next password in the list
                if (!decryptedText.matches("^\\p{ASCII}+$")) {
                    System.out.println("Does not work: " + list[i]);
                    continue attack;

                } else {
                    // If the decrypted text is all ASCII characters, the decryption was successful
                    // and we can stop trying passwords
                    System.out.println("Attack Successful");
                    System.out.println("Password is : " + list[i]);;
                    password = list[i]; //The password is returned
                    break;
                }
            }
        }

        // Decrypt the file data using the password
        byte[] decryptedData = decryptData(password, encryptedData);
        String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);

        // Clear the text area and display the decrypted text
        textBody.setText("");
        textBody.setText(decryptedText);

        // Set the title of the window to the filename
        setTitle(filename);
    }

    protected void menuItemPrintActionPerformed(ActionEvent event) {
        // Create a new PrinterJob object
        PrinterJob job = PrinterJob.getPrinterJob();
        
        // Create a Printable object that will be used to print the document
        Printable document = new Printable() {
            private JComponent textarea;

			@Override
            public int print(Graphics graphics, PageFormat pageFormat, int pageIndex) throws PrinterException {
                // If the page index is greater than 0, there are no more pages to print
                if (pageIndex > 0) {
                    return NO_SUCH_PAGE;
                }
                // Get a Graphics2D object from the Graphics object passed in
                Graphics2D g2d = (Graphics2D) graphics;
                // Translate the origin of the graphics context to the printable area of the page
                g2d.translate(pageFormat.getImageableX(), pageFormat.getImageableY());
                textarea = null;
                textarea.printAll(g2d);
                return PAGE_EXISTS;
            }
        };
        
        // Display the print dialog and get the user's selection
        boolean ok = job.printDialog();
        if (ok) {
            try {
                // Set the Printable object on the PrinterJob object
                job.setPrintable(document);
                // Start the print job
                job.print();
            } catch (PrinterException ex) {
                // If there is a PrinterException, display an error message to the user
                JOptionPane.showMessageDialog(null, "Printing failed: " + ex.getMessage(), "Print Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }


    protected void menuInfoDetailsActionPerformed(ActionEvent event) {
        JOptionPane.showMessageDialog(this, "Student Name: Andrew Gilbey \n Student Number: C00263656 \n Title: Secure Notepad \n Start Date: 03/01/23 \n End Date: 07/03/23",
            "Writer Information", JOptionPane.INFORMATION_MESSAGE);
    }

    protected void menuInfoActionPerformed(ActionEvent event) {

    }
    //Listeners
    protected void menuItemFileActionPerformed(ActionEvent event) {
        fileNew();

    }

    // Getters & Setters
    public JTextArea getTextBody() {
        return textBody;
    }

    public void setTextBody(String input) {
        this.textBody.setText(input);
    }

    // Methods
    public void fileNew() {
        textBody.setText(null);
        setTitle("'Untitled.txt'" + " - Secure Notepad");
    }
    
    // Cryptography
    private byte[] encryptText(String text, String password) throws Exception {
        byte[] salt = generateSalt();
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
        byte[] encryptedText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        byte[] saltIvEncryptedText = new byte[32 + encryptedText.length];
        System.arraycopy(salt, 0, saltIvEncryptedText, 0, 16);
        System.arraycopy(iv, 0, saltIvEncryptedText, 16, 16);
        System.arraycopy(encryptedText, 0, saltIvEncryptedText, 32, encryptedText.length);
        return saltIvEncryptedText;
    }
    
	private byte[] decryptData(String password, byte[] encryptedData) throws IOException {
        try {
            // Parse the salt and IV from the encrypted data
            byte[] salt = Arrays.copyOfRange(encryptedData, 0, 16);
            byte[] iv = Arrays.copyOfRange(encryptedData, 16, 32);
            byte[] ciphertext = Arrays.copyOfRange(encryptedData, 32, encryptedData.length);

            // Derive the key from the password and salt
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Decrypt the ciphertext using AES in CTR mode
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] plaintext = cipher.doFinal(ciphertext);
            return plaintext;
        } catch (Exception e) {
            throw new IOException("Error decrypting file: " + e.getMessage());
        }
    }
	
	// dictionary Attack
	 public void readList(String[] array) {
	        for (int i = 0; i < array.length; i++) {
	            System.out.println(array[i]);
	        }
	    }

	    //Read in the list and then transfer it's contents to a String array using a buffered reader object.
	    //Exception handling is included - if the text file cannot be found the array will be populated with the word ERROR.
	    public String[] buildList() throws IOException, Exception {
	        //BufferedReader reader;
	        String[] list = new String[1000];
	        int i = 0;
	        try (BufferedReader reader = new BufferedReader(new FileReader("src/10-million-password-list-top-1000.txt"))) {
	            String line;
	            while ((line = reader.readLine()) != null) {
	                list[i] = line;
	                i++;
	            }
	        } catch (FileNotFoundException e) {
	            System.out.println("File cannot be found. Please ensure that the file named '1000CommonPasswords.txt' is located in the src folder!!");
	            JOptionPane.showMessageDialog(new JFrame(), "File cannot be found." + "\n" +"Please ensure that the list of 10-million-password-list-top-1000.txt file is located in the src folder!", "Critical Dependancy Missing",
	                JOptionPane.ERROR_MESSAGE);

	            for (i = 0; i < list.length; i++) {
	                list[i] = "ERROR";
	            }
	        }
	        return list;
	    }
	    





}