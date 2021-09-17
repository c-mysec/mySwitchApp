package com.brf.myswitchapp;

import androidx.appcompat.app.AppCompatActivity;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {
    UdpUtil udpUtil;
    JavaScriptInterface ji;
    private WebViewClient mWebClient = new WebViewClient() {
        /**
         * It is a good idea to let proper web browsers handle URLs you don't know otherwise
         * you could be putting your users to danger by injecting JavaScript interface
         */

        @SuppressWarnings("deprecation")
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            final Uri uri = Uri.parse(url);
            return handleUri(uri);
        }

        @TargetApi(Build.VERSION_CODES.N)
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            final Uri uri = request.getUrl();
            return handleUri(uri);
        }

        private boolean handleUri(final Uri uri) {
            String host = uri.getHost(); //Host is null when user clicked on email, phone number, ...
            if (host != null) return false;
            if (host == null) return false;
            if (host != null && host.equals("c-mysec.github.io")) {
            //if (host != null && (host.equals("192.168.15.14")
            //        || host.equals("fonts.googleapis.com")
            //        || host.equals("fonts.gstatic.com"))) {
                // This is my web site, so do not override; let my WebView load the page
                return false;
            }
            else {
                // Otherwise, the link is not for a page on my site, so launch another Activity that handles URLs or anything else (email, phone number, ...)
                Intent intent = new Intent(Intent.ACTION_VIEW, uri);
                startActivity(intent);
                return true;
            }
        }
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed(); // Ignore SSL certificate errors
        }
    };
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getSupportActionBar().hide();
        WebView myWebView = (WebView) findViewById(R.id.webview);
        myWebView.setWebViewClient(mWebClient);
        WebSettings webSettings = myWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setDomStorageEnabled(true);
        Crypto crypto = new Crypto(this);
        udpUtil = new UdpUtil(this, 5577, myWebView, crypto);
        ji = new JavaScriptInterface(this, myWebView, udpUtil, crypto);
        myWebView.addJavascriptInterface(ji, "Android");
        myWebView.loadUrl("https://c-mysec.github.io/");//"https://192.168.15.14:4200");
        //myWebView.loadUrl("https://192.168.15.14:4200");
        udpUtil.start();
    }
}
/*
https://www.tanelikorri.com/tutorial/android/communication-between-application-and-webview/

 */