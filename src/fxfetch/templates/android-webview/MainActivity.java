package app.shell;

import android.app.Activity;
import android.os.Bundle;
import android.net.Uri;
import android.net.http.SslError;
import android.view.Menu;
import android.view.MenuItem;
import android.webkit.SslErrorHandler;
import android.webkit.ServiceWorkerClient;
import android.webkit.ServiceWorkerController;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.Toolbar;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

public final class MainActivity extends Activity {
    private static final String ASSET_HOST = "appassets.androidplatform.net";
    private static final String OFFLINE_URL = "https://appassets.androidplatform.net/site/index.html";
    private WebView view;
    private String entryUrl;
    private boolean hasOffline;
    private boolean hasOfflineFont;
    private volatile boolean offlineMode;
    private boolean sslRejected;

    private static boolean isHttp(Uri uri) {
        return "https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme());
    }

    private static boolean isLocalAsset(Uri uri) {
        if (!"https".equals(uri.getScheme()) || !ASSET_HOST.equals(uri.getAuthority())
                || uri.getQuery() != null) return false;
        String path = uri.getPath();
        if (path == null || !path.equals(uri.getEncodedPath())) return false;
        return "/licenses/offline-sc.txt".equals(path) || "/site/assets/offline-sc.otf".equals(path)
                || "/site/index.html".equals(path) || "/site/assets/style.css".equals(path)
                || path.matches("/site/assets/[a-f0-9]{64}\\.(png|jpg|jpeg|webp)");
    }

    private static WebResourceResponse blocked() {
        return new WebResourceResponse("text/plain", "UTF-8", 403, "Forbidden",
                new HashMap<String, String>(), new ByteArrayInputStream(new byte[0]));
    }

    private WebResourceResponse localResponse(Uri uri) {
        if (!isLocalAsset(uri)) return blocked();
        String path = uri.getPath();
        String mime = "text/html";
        String encoding = "UTF-8";
        if (path.endsWith(".otf")) { mime = "font/otf"; encoding = null; }
        else if (path.endsWith(".txt")) mime = "text/plain";
        else if (path.endsWith(".css")) mime = "text/css";
        else if (path.endsWith(".png")) { mime = "image/png"; encoding = null; }
        else if (path.endsWith(".jpg") || path.endsWith(".jpeg")) { mime = "image/jpeg"; encoding = null; }
        else if (path.endsWith(".webp")) { mime = "image/webp"; encoding = null; }
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Cache-Control", "no-store");
        headers.put("X-Content-Type-Options", "nosniff");
        headers.put("Content-Security-Policy", "default-src 'none'; img-src 'self'; font-src 'self'; style-src 'self' 'unsafe-inline'; "
                + "script-src 'none'; connect-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'");
        try {
            return new WebResourceResponse(mime, encoding, 200, "OK", headers,
                    getAssets().open(path.substring(1)));
        } catch (IOException error) {
            return blocked();
        }
    }

    private void openOffline() {
        if (!hasOffline) return;
        offlineMode = true;
        view.stopLoading();
        WebSettings settings = view.getSettings();
        settings.setJavaScriptEnabled(false);
        settings.setDomStorageEnabled(false);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setBlockNetworkLoads(true);
        ServiceWorkerController.getInstance().getServiceWorkerWebSettings().setBlockNetworkLoads(true);
        view.loadUrl(OFFLINE_URL);
    }

    private void openOnline() {
        view.stopLoading();
        offlineMode = false;
        sslRejected = false;
        WebSettings settings = view.getSettings();
        settings.setBlockNetworkLoads(false);
        ServiceWorkerController.getInstance().getServiceWorkerWebSettings().setBlockNetworkLoads(false);
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        view.loadUrl(entryUrl);
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        try (InputStream input = getAssets().open("config.json")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int count;
            while ((count = input.read(buffer)) != -1) bytes.write(buffer, 0, count);
            JSONObject config = new JSONObject(bytes.toString("UTF-8"));
            entryUrl = config.getString("url");
            hasOffline = config.optBoolean("offline", false);
            try (InputStream font = getAssets().open("site/assets/offline-sc.otf")) {
                hasOfflineFont = font.read() != -1;
            } catch (IOException missing) { hasOfflineFont = false; }
            if (!isHttp(Uri.parse(entryUrl))) { finish(); return; }
        } catch (Exception error) {
            finish();
            return;
        }
        view = new WebView(this);
        WebSettings settings = view.getSettings();
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSupportMultipleWindows(false);
        WebView.setWebContentsDebuggingEnabled(false);
        ServiceWorkerController workers = ServiceWorkerController.getInstance();
        workers.getServiceWorkerWebSettings().setAllowFileAccess(false);
        workers.getServiceWorkerWebSettings().setAllowContentAccess(false);
        workers.setServiceWorkerClient(new ServiceWorkerClient() {
            @Override public WebResourceResponse shouldInterceptRequest(WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (offlineMode || !isHttp(uri) || ASSET_HOST.equalsIgnoreCase(uri.getHost())) return blocked();
                return null;
            }
        });
        view.setWebViewClient(new WebViewClient() {
            private boolean refuse(Uri uri) {
                return offlineMode ? !isLocalAsset(uri)
                        : !isHttp(uri) || ASSET_HOST.equalsIgnoreCase(uri.getHost());
            }
            @Override public boolean shouldOverrideUrlLoading(WebView web, WebResourceRequest request) {
                return refuse(request.getUrl());
            }
            @Override public boolean shouldOverrideUrlLoading(WebView web, String url) {
                return refuse(Uri.parse(url));
            }
            @Override public WebResourceResponse shouldInterceptRequest(WebView web, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (offlineMode) return localResponse(uri);
                if (!isHttp(uri) || ASSET_HOST.equalsIgnoreCase(uri.getHost())) return blocked();
                return null;
            }
            @Override public void onReceivedError(WebView web, WebResourceRequest request, WebResourceError error) {
                // Failed subresources never replace the main page. Certificate failures remain cancelled.
                if (request.isForMainFrame() && !offlineMode && hasOffline && !sslRejected
                        && isHttp(request.getUrl()) && !ASSET_HOST.equalsIgnoreCase(request.getUrl().getHost())
                        && error.getErrorCode() != WebViewClient.ERROR_FAILED_SSL_HANDSHAKE) openOffline();
            }
            @Override public void onReceivedSslError(WebView web, SslErrorHandler handler, SslError error) {
                sslRejected = true;
                handler.cancel();
            }
        });
        if (hasOffline) {
            LinearLayout layout = new LinearLayout(this);
            layout.setOrientation(LinearLayout.VERTICAL);
            Toolbar toolbar = new Toolbar(this);
            toolbar.setTitle(getTitle());
            layout.addView(toolbar, new LinearLayout.LayoutParams(-1, -2));
            layout.addView(view, new LinearLayout.LayoutParams(-1, 0, 1));
            setContentView(layout);
            setActionBar(toolbar);
        } else setContentView(view);
        // Try the complete original URL first. Only the explicit menu action retries it.
        openOnline();
    }

    @Override public boolean onCreateOptionsMenu(Menu menu) {
        if (hasOffline) {
            menu.add(Menu.NONE, 1, 1, "离线页面");
            menu.add(Menu.NONE, 2, 2, "重新联网");
            if (hasOfflineFont) menu.add(Menu.NONE, 3, 3, "字体许可");
        }
        return super.onCreateOptionsMenu(menu) || hasOffline;
    }

    @Override public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == 1) { openOffline(); return true; }
        if (item.getItemId() == 3 && hasOfflineFont) {
            openOffline();
            view.loadUrl("https://" + ASSET_HOST + "/licenses/offline-sc.txt");
            return true;
        }
        if (item.getItemId() == 2) { openOnline(); return true; }
        return super.onOptionsItemSelected(item);
    }

    @Override public void onBackPressed() {
        if (!offlineMode && view.canGoBack()) view.goBack();
        else super.onBackPressed();
    }

    @Override protected void onDestroy() {
        if (view != null) {
            ServiceWorkerController workers = ServiceWorkerController.getInstance();
            workers.getServiceWorkerWebSettings().setBlockNetworkLoads(true);
            workers.setServiceWorkerClient(null);
            view.stopLoading();
            view.destroy();
        }
        super.onDestroy();
    }
}
