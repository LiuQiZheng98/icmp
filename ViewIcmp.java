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

    //��̬����ѡ��,Ĭ��Ϊ0
    private static int n = 0;
    //��̬����
    private static NetworkInterface[] MyDevices = JpcapCaptor.getDeviceList();

    //����
    private JPanel p = new JPanel();
    private JPanel p_North = new JPanel();
    private JPanel p_Center = new JPanel();
    private JPanel p_South = new JPanel();
    private JPanel p_North_North = new JPanel();
    private JPanel p_South_North = new JPanel();

    //label
    private JLabel lab_Select = new JLabel("ѡ������");
    private JLabel lab_PingAdress = new JLabel("��дҪping�ĵ�ַ");
    //���
    private JTable table_NetworkCard = null;
    private JScrollPane jsp_NetworkCard = null;
    private JScrollPane jsp_JpacpPocket = null;
    private JScrollPane jsp_Ping = null;
    //�����ı���
    JTextArea txt_JpacpPacket = new JTextArea();
    JTextArea txt_Ping = new JTextArea();
    //�ı���
    JTextField txt_NetworkCard = new JTextField();
    JTextField txt_PingAdress = new JTextField();
    //��ť
    JButton btn_SelectNetworkCard = new JButton("ѡ��ץ������");
    JButton btn_JpacpPacket = new JButton("��ʼץ��");
    JButton btn_Ping = new JButton("Ping");
    //����
    Font font=new Font("����",Font.BOLD,28);

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
        table_NetworkCard.setFont(new Font("����",Font.BOLD,18));


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
        double width = Toolkit.getDefaultToolkit().getScreenSize().width; //�õ���ǰ��Ļ�ֱ��ʵĸ�
        double height = Toolkit.getDefaultToolkit().getScreenSize().height;//�õ���ǰ��Ļ�ֱ��ʵĿ�
//        this.setSize((int)width,(int)height);
        this.setSize(1200,800);
        this.setTitle("Icmp���ķ����Լ�Ping����");
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
        int caplen = 1512;  //ip������󳤶�
        boolean promiscCheck = true;

        //ץȡ�����
        try{
            jpcapCaptor = JpcapCaptor.openDevice(MyDevices[n], caplen, promiscCheck, 50);//�����ӿڡ�ip������󳤶ȡ��Ƿ���û���ģʽ����������ݰ��ĳ�ʱ���ã�������Ϊ���룩��
            //����ģʽ�У����Բ����������ݰ�������ԴMAC��Ŀ��MAC��ַ��򿪵�����ӿڵ�MAC��ַ����ͬ��
            //���ǻ���ģʽ��ֻ�ܲ��������������ͺͽ��յ����ݰ���
        }catch(IOException e)
        {
            e.printStackTrace();
        }

        /*----------�ڶ���ץ��-----------------*/


        int i = 0;
        while(i < 4)        //ץ���
        {
            Packet capturedPacket  = jpcapCaptor.getPacket(); //ץ��



            if(capturedPacket instanceof IPPacket && ((IPPacket)capturedPacket).version == 4)
            {



                IPPacket ipPacket = (IPPacket)capturedPacket;//ǿת  ������İ�ת��ΪIPPacket����



                String protocol ="";        //Э��
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
                        str_JpacpPacket += "header����\n";
                        str_JpacpPacket += tools.bytesToHexString(capturedPacket.header) + "\n";

                        str_JpacpPacket += "data����\n";


                        str_JpacpPacket += tools.bytesToHexString(capturedPacket.data) + "\n";

                    }



                    str_JpacpPacket += "Э�飺" + protocol + "\n";

                    str_JpacpPacket += "ԴIP " + ipPacket.src_ip.getHostAddress() + "\n";

                    str_JpacpPacket += "Ŀ��IP " + ipPacket.dst_ip.getHostAddress() + "\n";

                    str_JpacpPacket += "Դ�������� " + ipPacket.src_ip + "\n";

                    str_JpacpPacket += "Ŀ���������� " + ipPacket.dst_ip + "\n";

                    str_JpacpPacket += "���ȣ�" + ipPacket.length + "\n";


                    str_JpacpPacket += "��ʶ��" + ipPacket.ident + "\n";

                    str_JpacpPacket += "Ƭƫ�ƣ�" + ipPacket.offset + "\n";

                    str_JpacpPacket += "����ʱ�䣺"+ ipPacket.hop_limit + "\n";


                    str_JpacpPacket += "----------------------------------------------\n";

                }
//
            }
        }

        txt_JpacpPacket.setText(str_JpacpPacket);
    }

    public void btn_PingClick(){
        String ipAddress = txt_PingAdress.getText().trim();         //��ȡip��ַ��Ϣ
        String str_Ping = "";
        String line=null;
        try {
            Process process=Runtime.getRuntime().exec("ping "+ipAddress);
            BufferedReader bufferedReader=new BufferedReader(new InputStreamReader(process.getInputStream()));
            str_Ping += "����ping������ping " + ipAddress + "\n";
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
