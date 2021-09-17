package com.brf.myswitchapp;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.util.Base64;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;

import com.thanosfisherman.wifiutils.WifiUtils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;


public class JavaScriptInterface {
    Activity activity;
    WebView webView;
    UdpUtil udpUtil;
    Crypto crypto;
    BroadcastReceiver wifiScanReceiver;
    JavaScriptInterface(Activity a, WebView w, UdpUtil u, Crypto c) {
        activity = a;
        webView = w;
        crypto = c;
        udpUtil = u;
    }
    @JavascriptInterface
    public void setPassword(final String passwd) {
        // JavaScript doesn't run on the UI thread, make sure you do anything UI related like this
        // You don't need this for the Toast, but otherwise it's a good idea
        String pwd = passwd;
        (activity).runOnUiThread(new Runnable() {
            @Override
            public void run() {
                SharedPreferences sharedPref = activity.getPreferences(Context.MODE_PRIVATE);
                SharedPreferences.Editor editor = sharedPref.edit();
                editor.putString("pass", passwd);
                editor.commit();
                crypto.genkeys(passwd);
            }
        });
    }
    @JavascriptInterface
    public void broadcastBase64(final String msg) {
        byte[] m = android.util.Base64.decode(msg, Base64.DEFAULT);
        crypto.printByteArray("broadCast clean: ", m);
        byte[] buffer = crypto.signMsg(m);
        crypto.printByteArray("broadCast crypto: ", buffer);
        udpUtil.sendBroadcast(buffer);
    }
    @JavascriptInterface
    public void scanWifi() {
        WifiUtils.withContext(activity).scanWifi(this::getScanResults).start();
    }
    private void getScanResults(@NonNull final List<ScanResult> results)
    {
        if (results.isEmpty())
        {
            Log.i("Javascript", "SCAN RESULTS IT'S EMPTY");
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    JSONArray array = new JSONArray();
                    for (ScanResult res: results) {
                        JSONObject json = new JSONObject();
                        json.put("level", res.level);
                        json.put("ssid", res.SSID);
                        array.put(json);
                    }
                    webView.loadUrl("javascript:wifiScanResult('" + array.toString() + "');");
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        });
        Log.i("Javascript", "GOT SCAN RESULTS " + results);
    }
}
