package Ping.view;

import Ping.tools;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class ViewIcmp extends JFrame {

    //静态网卡选择,默认为0
    private static int n = 0;
    //静态网卡
    private static NetworkInterface[] MyDevices = JpcapCaptor.getDeviceList();

    //界面
    private JPanel p = new JPanel();
    private JPanel p_North = new JPanel();
    private JPanel p_Center = new JPanel();
    private JPanel p_South = new JPanel();
    private JPanel p_North_North = new JPanel();
    private JPanel p_South_North = new JPanel();

    //label
    private JLabel lab_Select = new JLabel("选择网卡");
    private JLabel lab_PingAdress = new JLabel("填写要ping的地址");
    //表格
    private JTable table_NetworkCard = null;
    private JScrollPane jsp_NetworkCard = null;
    private JScrollPane jsp_JpacpPocket = null;
    private JScrollPane jsp_Ping = null;
    //多行文本框
    JTextArea txt_JpacpPacket = new JTextArea();
    JTextArea txt_Ping = new JTextArea();
    //文本框
    JTextField txt_NetworkCard = new JTextField();
    JTextField txt_PingAdress = new JTextField();
    //按钮
    JButton btn_SelectNetworkCard = new JButton("选择抓包网卡");
    JButton btn_JpacpPacket = new JButton("开始抓包");
    JButton btn_Ping = new JButton("Ping");
    //字体
    Font font=new Font("宋体",Font.BOLD,28);

    public ViewIcmp(){
        p.setLayout(new GridLayout(3, 1));
        p_North.setLayout(new BorderLayout());
        p_North_North.setLayout(new GridLayout(1, 3));
        p_South_North.setLayout(new GridLayout(1, 3));
        p_Center.setLayout(new GridLayout(2, 1));
        p_South.setLayout(new GridLayout(2, 1));

        initJspNetworkCard();
        jsp_NetworkCard = new JScrollPane(table_NetworkCard);

        lab_Select.setHorizontalAlignment(SwingConstants.CENTER);lab_Select.setFont(font);
        lab_PingAdress.setHorizontalAlignment(SwingConstants.CENTER);lab_PingAdress.setFont(font);
        btn_Ping.setFont(font);btn_JpacpPacket.setFont(font);btn_SelectNetworkCard.setFont(font);
        table_NetworkCard.setFont(new Font("宋体",Font.BOLD,18));


        txt_JpacpPacket.setLineWrap(true);
        txt_JpacpPacket.setEditable(false);txt_JpacpPacket.setWrapStyleWord(true);txt_JpacpPacket.setFont(font);
        jsp_JpacpPocket = new JScrollPane(txt_JpacpPacket);
        txt_Ping.setLineWrap(true);
        txt_Ping.setEditable(false);txt_Ping.setWrapStyleWord(true);txt_Ping.setFont(font);
        jsp_Ping = new JScrollPane(txt_Ping);


        p_North_North.add(lab_Select);p_North_North.add(txt_NetworkCard);p_North_North.add(btn_SelectNetworkCard);
        p_North.add(p_North_North, BorderLayout.NORTH);
        p_North.add(jsp_NetworkCard, BorderLayout.CENTER);

        p_Center.add(btn_JpacpPacket);
        p_Center.add(jsp_JpacpPocket);

        p_South_North.add(lab_PingAdress);p_South_North.add(txt_PingAdress);p_South_North.add(btn_Ping);
        p_South.add(p_South_North);
        p_South.add(jsp_Ping);

        p.add(p_North);
        p.add(p_Center);
        p.add(p_South);

        btn_SelectNetworkCard.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                btn_SelectNetworkCardClick();
            }
        });

        btn_JpacpPacket.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                btn_JpacpPacketClick();
            }
        });

        btn_Ping.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                btn_PingClick();
            }
        });


        this.getContentPane().add(p);
        this.setVisible(true);
        double width = Toolkit.getDefaultToolkit().getScreenSize().width; //得到当前屏幕分辨率的高
        double height = Toolkit.getDefaultToolkit().getScreenSize().height;//得到当前屏幕分辨率的宽
//        this.setSize((int)width,(int)height);
        this.setSize(1200,800);
        this.setTitle("Icmp报文分析以及Ping操作");
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    public void initJspNetworkCard(){
        String[] cols = {"name","description"};


        String[][] allDevices = new String[MyDevices.length][2];
        int i = 0;
        for(NetworkInterface n : MyDevices){
            allDevices[i][0] = n.name;
            allDevices[i++][1] = n.description;
        }

        String[][] rows = allDevices;
        table_NetworkCard = new JTable(rows, cols);


    }

    public void btn_SelectNetworkCardClick(){
        String x = txt_NetworkCard.getText().trim();
        if (!x.equals(""))
            n = Integer.parseInt(x) - 1;
        else
            n = 0;
    }

    public void btn_JpacpPacketClick(){
        String str_JpacpPacket = "";


        JpcapCaptor jpcapCaptor = null;
        int caplen = 1512;  //ip报文最大长度
        boolean promiscCheck = true;

        //抓取第五个
        try{
            jpcapCaptor = JpcapCaptor.openDevice(MyDevices[n], caplen, promiscCheck, 50);//网卡接口、ip报文最大长度、是否采用混乱模式、捕获的数据包的超时设置（数量级为毫秒）。
            //混乱模式中，可以捕获所有数据包，即便源MAC或目的MAC地址与打开的网络接口的MAC地址不相同。
            //而非混乱模式中只能捕获由宿主机发送和接收的数据包。
        }catch(IOException e)
        {
            e.printStackTrace();
        }

        /*----------第二步抓包-----------------*/


        int i = 0;
        while(i < 4)        //抓五次
        {
            Packet capturedPacket  = jpcapCaptor.getPacket(); //抓包



            if(capturedPacket instanceof IPPacket && ((IPPacket)capturedPacket).version == 4)
            {



                IPPacket ipPacket = (IPPacket)capturedPacket;//强转  将捕获的包转换为IPPacket类型



                String protocol ="";        //协议
                switch(new Integer(ipPacket.protocol))
                {
                    case 1:protocol = "ICMP";break;
                    case 2:protocol = "IGMP";break;
                    case 6:protocol = "TCP";break;
                    case 8:protocol = "EGP";break;
                    case 9:protocol = "IGP";break;
                    case 17:protocol = "UDP";break;
                    case 41:protocol = "IPv6";break;
                    case 89:protocol = "OSPF";break;
                    default : break;
                }

                if (protocol.equals("ICMP")) {
                    i++;
                    str_JpacpPacket += ipPacket.toString();
                    str_JpacpPacket += "\n";
                    if(capturedPacket.header!=null){
                        str_JpacpPacket += "header如下\n";
                        str_JpacpPacket += tools.bytesToHexString(capturedPacket.header) + "\n";

                        str_JpacpPacket += "data如下\n";


                        str_JpacpPacket += tools.bytesToHexString(capturedPacket.data) + "\n";

                    }



                    str_JpacpPacket += "协议：" + protocol + "\n";

                    str_JpacpPacket += "源IP " + ipPacket.src_ip.getHostAddress() + "\n";

                    str_JpacpPacket += "目的IP " + ipPacket.dst_ip.getHostAddress() + "\n";

                    str_JpacpPacket += "源主机名： " + ipPacket.src_ip + "\n";

                    str_JpacpPacket += "目的主机名： " + ipPacket.dst_ip + "\n";

                    str_JpacpPacket += "长度：" + ipPacket.length + "\n";


                    str_JpacpPacket += "标识：" + ipPacket.ident + "\n";

                    str_JpacpPacket += "片偏移：" + ipPacket.offset + "\n";

                    str_JpacpPacket += "生存时间："+ ipPacket.hop_limit + "\n";


                    str_JpacpPacket += "----------------------------------------------\n";

                }
//
            }
        }

        txt_JpacpPacket.setText(str_JpacpPacket);
    }

    public void btn_PingClick(){
        String ipAddress = txt_PingAdress.getText().trim();         //获取ip地址信息
        String str_Ping = "";
        String line=null;
        try {
            Process process=Runtime.getRuntime().exec("ping "+ipAddress);
            BufferedReader bufferedReader=new BufferedReader(new InputStreamReader(process.getInputStream()));
            str_Ping += "运行ping操作，ping " + ipAddress + "\n";
            while((line=bufferedReader.readLine())!=null){
                str_Ping += line + "\n";
            }
        } catch (Exception e) {
            str_Ping += e.getMessage() + "\n";
        }

        txt_Ping.setText(str_Ping);

    }
    public static void main(String[] args) {
        ViewIcmp viewIcmp = new ViewIcmp();
    }
}
