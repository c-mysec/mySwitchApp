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
import android.util.Base64;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import androidx.core.app.ActivityCompat;

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
    WifiManager wifiManager;
    private final int MY_PERMISSIONS_ACCESS_COARSE_LOCATION = 1;
    JavaScriptInterface(Activity a, WebView w, UdpUtil u, Crypto c) {
        activity = a;
        webView = w;
        crypto = c;
        udpUtil = u;
        wifiManager = (WifiManager)
                activity.getSystemService(Context.WIFI_SERVICE);

        wifiScanReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent intent) {
                boolean success = intent.getBooleanExtra(
                        WifiManager.EXTRA_RESULTS_UPDATED, false);
                if (success) {
                    scanSuccess();
                } else {
                    // scan failure handling
                    scanSuccess();
                }
            }
        };

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        activity.registerReceiver(wifiScanReceiver, intentFilter);

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
        if (ActivityCompat.checkSelfPermission(activity, Manifest.permission.ACCESS_COARSE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                    activity,
                    new String[]{Manifest.permission.ACCESS_COARSE_LOCATION},
                    MY_PERMISSIONS_ACCESS_COARSE_LOCATION);
        } else {
            boolean success = wifiManager.startScan();
            Log.i("Javascript", success?"1":"0");
        }
    }
    private void scanSuccess() {
        List<ScanResult> results = wifiManager.getScanResults();
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
    }
}
