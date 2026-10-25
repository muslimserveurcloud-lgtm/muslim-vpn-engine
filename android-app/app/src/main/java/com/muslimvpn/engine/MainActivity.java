package com.muslimvpn.engine;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.view.View;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIHostName;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Collections;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private EditText configInput;
    private TextView status;
    private Button testButton;

    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private TextView label(String text, int size, int color) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(size);
        view.setTextColor(color);
        return view;
    }

    private void space(LinearLayout parent, int height) {
        View v = new View(this);
        parent.addView(v, new LinearLayout.LayoutParams(1, dp(height)));
    }

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(7, 17, 31));
        getWindow().setNavigationBarColor(Color.rgb(7, 17, 31));

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(22), dp(30), dp(22), dp(28));
        root.setBackgroundColor(Color.rgb(7, 17, 31));
        scroll.addView(root);

        TextView brand = label("MUSLIM VPN", 28, Color.WHITE);
        brand.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(brand);

        TextView subtitle = label("ENGINE  •  ANDROID", 13, Color.rgb(0, 217, 255));
        root.addView(subtitle);

        space(root, 26);

        TextView heading = label("Test de connexion", 22, Color.WHITE);
        heading.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(heading);

        space(root, 8);
        root.addView(label(
            "Colle un lien VLESS pour vérifier sa configuration et tester la connexion TLS au serveur.",
            15, Color.rgb(180, 195, 214)));

        space(root, 18);

        configInput = new EditText(this);
        configInput.setHint("vless://UUID@serveur:443?security=tls...");
        configInput.setHintTextColor(Color.rgb(115, 135, 158));
        configInput.setTextColor(Color.WHITE);
        configInput.setTextSize(14);
        configInput.setGravity(Gravity.TOP | Gravity.START);
        configInput.setMinLines(4);
        configInput.setMaxLines(8);
        configInput.setPadding(dp(14), dp(14), dp(14), dp(14));
        configInput.setBackgroundColor(Color.rgb(19, 34, 53));
        configInput.setInputType( android.text.InputType.TYPE_CLASS_TEXT
            | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
            | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        root.addView(configInput, new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(150)));

        space(root, 16);

        testButton = new Button(this);
        testButton.setText("TESTER LE SERVEUR");
        testButton.setTextColor(Color.rgb(7, 17, 31));
        testButton.setBackgroundTintList(
            android.content.res.ColorStateList.valueOf(Color.rgb(0, 217, 255)));
        root.addView(testButton, new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(54)));

        space(root, 22);

        status = label("ÉTAT : EN ATTENTE\n\nAucun test effectué.", 15, Color.WHITE);
        status.setPadding(dp(15), dp(15), dp(15), dp(15));
        status.setBackgroundColor(Color.rgb(19, 34, 53));
        root.addView(status);

        space(root, 18);
        root.addView(label(
            "TRANSPARENCE\nCette version teste la configuration et la négociation TLS. "
            + "Elle ne crée pas encore de tunnel VPN et ne route pas le trafic des applications.",
            13, Color.rgb(180, 195, 214)));

        testButton.setOnClickListener(v -> runTest());
        setContentView(scroll);
    }

    private void runTest() {
        final String link = configInput.getText().toString().trim();
        if (link.isEmpty()) {
            status.setText("Entre d'abord un lien VLESS.");
            return;
        }

        final Uri uri;
        final String host;
        final String sni;
        final int port;

        try {
            uri = Uri.parse(link);
            if (!"vless".equalsIgnoreCase(uri.getScheme())) {
                throw new IllegalArgumentException("Le lien doit commencer par vless://");
            }

            String id = uri.getUserInfo();
            UUID.fromString(id == null ? "" : id);

            host = uri.getHost();
            port = uri.getPort();
            String security = uri.getQueryParameter("security");
            String transport = uri.getQueryParameter("type");
            sni = uri.getQueryParameter("sni");

            if (host == null || host.isEmpty() || port < 1 || port > 65535) {
                throw new IllegalArgumentException("Serveur ou port invalide.");
            }
            if (!"tls".equalsIgnoreCase(security)) {
                throw new IllegalArgumentException(
                    "Cette version de test exige security=tls. REALITY n'est pas pris en charge.");
            }
            if (transport != null && !transport.isEmpty()
                    && !"tcp".equalsIgnoreCase(transport)) {
                throw new IllegalArgumentException(
                    "Cette version de test exige le transport TCP.");
            }
        } catch (Exception e) {
            status.setText("CONFIGURATION INVALIDE\n\n" + safeMessage(e));
            return;
        }

        final String tlsName = (sni == null || sni.trim().isEmpty())
            ? host : sni.trim();

        testButton.setEnabled(false);
        status.setText("TEST EN COURS\n\nConnexion TCP et négociation TLS…");

        worker.execute(() -> {
            String result;
            SSLSocket ssl = null;
            Socket raw = null;

            try {
                raw = new Socket();
                raw.connect(new InetSocketAddress(host, port), 10000);
                raw.setSoTimeout(10000);

                SSLSocketFactory factory =
                    (SSLSocketFactory) SSLSocketFactory.getDefault();

                ssl = (SSLSocket) factory.createSocket(raw, tlsName, port, true);
                ssl.setSoTimeout(10000);

                SSLParameters parameters = ssl.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                parameters.setServerNames(
                    Collections.singletonList(new SNIHostName(tlsName)));
                ssl.setSSLParameters(parameters);
                ssl.startHandshake();

                result = "TLS RÉUSSI\n\n"
                    + "Serveur : " + host + ":" + port + "\n"
                    + "SNI : " + tlsName + "\n"
                    + "Version TLS : " + ssl.getSession().getProtocol() + "\n"
                    + "Chiffrement : " + ssl.getSession().getCipherSuite()
                    + "\n\nLe certificat a été vérifié.\n"
                    + "Attention : le protocole VLESS n'a pas encore été négocié ; "
                    + "aucun tunnel VPN n'a été créé.";

            } catch (Exception e) {
                result = "CONNEXION ÉCHOUÉE\n\n"
                    + safeMessage(e)
                    + "\n\nVérifie le réseau mobile, le serveur, le port, le SNI "
                    + "et le certificat TLS.";
            } finally {
                try {
                    if (ssl != null) ssl.close();
                    else if (raw != null) raw.close();
                } catch (Exception ignored) {}
            }

            final String finalResult = result;
            runOnUiThread(() -> {
                status.setText(finalResult);
                testButton.setEnabled(true);
            });
        });
    }

    private String safeMessage(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return e.getClass().getSimpleName();
        }
        return e.getClass().getSimpleName() + ": " + message;
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
