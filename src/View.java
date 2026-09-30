
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

public class View extends JFrame {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final JTextArea inputArea;
    private final JTextArea outputArea;

    public View() {
        super("AES - View");

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        JLabel title = new JLabel("Cryptage AES 128 bits");
        title.setFont(new Font("Arial", Font.BOLD, 20));
        title.setHorizontalAlignment(JLabel.CENTER);
        add(title, BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(10, 10));
        center.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        inputArea = new JTextArea();
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        inputArea.setFont(new Font("Arial", Font.PLAIN, 14));
        JScrollPane inputScroll = new JScrollPane(inputArea);
        inputScroll.setPreferredSize(new Dimension(450, 150));

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);
        outputArea.setFont(new Font("Arial", Font.PLAIN, 14));
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputScroll.setPreferredSize(new Dimension(450, 150));

        JPanel labels = new JPanel(new BorderLayout(10, 10));
        labels.add(new JLabel("Message :"), BorderLayout.NORTH);
        labels.add(inputScroll, BorderLayout.CENTER);
        labels.add(new JLabel("Résultat :"), BorderLayout.SOUTH);

        center.add(labels, BorderLayout.NORTH);
        center.add(outputScroll, BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 10));
        JButton encryptButton = new JButton("Chiffrer");
        JButton decryptButton = new JButton("Déchiffrer");

        encryptButton.addActionListener(e -> chiffrer());
        decryptButton.addActionListener(e -> dechiffrer());

        buttons.add(encryptButton);
        buttons.add(decryptButton);
        add(buttons, BorderLayout.SOUTH);

        setSize(520, 450);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void chiffrer() {
        try {
            String message = inputArea.getText();
            if (message == null || message.isEmpty()) {
                outputArea.setText("");
                return;
            }

            AES aes = new AES(128);
            int[] bits = aes.stringToBits(message);
            int[] cipher = aes.crypte(bits);
            outputArea.setText(aes.bitsToString(cipher));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Erreur", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void dechiffrer() {
        try {
            String message = inputArea.getText();
            if (message == null || message.isEmpty()) {
                outputArea.setText("");
                return;
            }

            AES aes = new AES(128);
            int[] bits = aes.stringToBits(message);
            int[] plain = aes.decrypte(bits);
            outputArea.setText(aes.bitsToString(plain));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Erreur", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new View());
    }
}
