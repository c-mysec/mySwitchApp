package com.brf.myswitchapp;

import android.app.Activity;
import android.content.Context;
import android.net.DhcpInfo;
import android.net.wifi.WifiManager;
import android.util.Base64;
import android.util.Log;
import android.webkit.WebView;
import android.widget.Toast;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.Arrays;

public class UdpUtil implements Runnable {
    private static final String TAG = "UdpUtil";
    private int mPort = 5577;
    private Activity mActivity;
    private WebView mWebView;
    DatagramSocket socket;
    boolean running;
    Crypto crypto;
    private String mMyip;
    public UdpUtil(Activity a, int port, WebView webView, Crypto c) {
        mActivity = a;
        mPort = port;
        mWebView = webView;
        crypto = c;
    }
    public void start() {
        new Thread(this).start();
    }
    public void sendBroadcast(byte[] sendData) {
        // Hack Prevent crash (sending should be done using an async task)
        //StrictMode.ThreadPolicy policy = new   StrictMode.ThreadPolicy.Builder().permitAll().build();
        //StrictMode.setThreadPolicy(policy);
        Runnable r = new Runnable() {
            @Override
            public void run() {
                try {
                    //Open a random port to send the package
                    DatagramSocket socket = new DatagramSocket();
                    socket.setBroadcast(true);
                    DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, getBroadcastAddress(), mPort);
                    socket.send(sendPacket);
                    System.out.println(getClass().getName() + "Broadcast packet sent to: " + getBroadcastAddress().getHostAddress());
                } catch (IOException e) {
                    Log.e(TAG, "IOException: " + e.getMessage());
                }
            }
        };
        new Thread(r).start();
    }

    InetAddress getBroadcastAddress() throws IOException {
        WifiManager wifi = (WifiManager) mActivity.getSystemService(Context.WIFI_SERVICE);
        DhcpInfo dhcp = wifi.getDhcpInfo();
        byte[] b = new byte[4];
        b[3] = (byte)(dhcp.ipAddress >> 24 & 0xff);
        b[2] = (byte)(dhcp.ipAddress >> 16 & 0xff);
        b[1] = (byte)(dhcp.ipAddress >> 8 & 0xff);
        b[0] = (byte)(dhcp.ipAddress & 0xff);
        InetAddress inetAddress = InetAddress.getByAddress(b);
        if (dhcp.netmask == 0) {
            try
            {
                NetworkInterface networkInterface = NetworkInterface.getByInetAddress(inetAddress);
                for (InterfaceAddress address : networkInterface.getInterfaceAddresses()) {
                    if (address.getBroadcast() != null && address.getBroadcast() instanceof Inet4Address) {
                        Log.e(TAG, "1BROADCAST IP ADDRESS" + address.getBroadcast().toString());
                        mMyip = address.getAddress().toString().substring(1);
                        return address.getBroadcast();
                    }
                }
            }
            catch (IOException exception)
            {
                Log.d("Exception:", exception.getMessage());
            }
        }
        int broadcast = (dhcp.ipAddress & 0x00ffffff) | 0xff000000;
        byte[] quads = new byte[4];
        for (int k = 0; k < 4; k++)
            quads[k] = (byte) ((broadcast >> k * 8) & 0xFF);
        mMyip = inetAddress.getAddress().toString().substring(1);
        Log.e(TAG, "2BROADCAST IP ADDRESS" + InetAddress.getByAddress(quads).toString());
        Log.e(TAG, "3 IP ADDRESS" + mMyip.toString());
        return InetAddress.getByAddress(quads);
    }
    public void setRunning(boolean running){
        this.running = running;
    }

    @Override
    public void run() {
        running = true;
        try {
            InetAddress ia = getBroadcastAddress();
            socket = new DatagramSocket(mPort, ia);
            Log.e(TAG, "UDP Server is running");
            while(running){
                byte[] buf = new byte[256];

                // receive request
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);     //this code block the program flow

                // send the response to the client at "address" and "port"
                InetAddress address = packet.getAddress();
                int port = packet.getPort();
                String dString = new java.util.Date().toString() + "\n"
                        + "Your address " + address.toString() + ":" + String.valueOf(port);
                //buf = dString.getBytes();
                //packet = new DatagramPacket(buf, buf.length, address, port);
                //socket.send(packet);
                if (packet.getLength() < crypto.minimumSize()) continue;
                byte[] b1 = Arrays.copyOf(buf, packet.getLength());
                byte[] b = crypto.openMsg(b1);
                String m = android.util.Base64.encodeToString(b, Base64.DEFAULT);
                Log.i(TAG, m);
                String ipA = address.toString().substring(1);
                if (!mMyip.equals((ipA))) {
                    mActivity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mWebView.loadUrl("javascript:broadcastReceivedBase64('" + ipA + "', '" + m + "');");
                        }
                    });
                }
            }

            Log.e(TAG, "UDP Server ended");

        } catch (java.net.SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(socket != null){
                socket.close();
                Log.e(TAG, "socket.close()");
            }
        }
    }
}
