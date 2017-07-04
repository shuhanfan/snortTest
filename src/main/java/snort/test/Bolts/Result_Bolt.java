package snort.test.Bolts;

import java.util.ArrayList;
import java.util.Map;
import backtype.storm.task.OutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.BasicOutputCollector;
import backtype.storm.topology.FailedException;
import backtype.storm.topology.IBasicBolt;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Tuple;
import backtype.storm.tuple.Values;

import java.io.*; 

import snort.test.Helpers.Packet_Header;
import snort.test.Helpers.Rule_Header;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Result_Bolt implements IBasicBolt{

	private BasicOutputCollector outputCollector;
	//private ArrayList<Rule_Header> rule_set;
	public FileOutputStream out;
	public FileWriter fw ;
	private String name_bolt;
	private int rpack1, rpack2, rpack3, ppack1, ppack2, ppack3, detect1, detect2, detect3;
	private long rflow1, rflow2,rflow3, pflow1, pflow2, pflow3;
	private long lastTime;
	private long curTime;
	private long rtime1, rtime2, rtime3;
	private long ptime1, ptime2, ptime3;
	private String msg1, protocol1, sip1, dip1, msg2, protocol2, sip2, dip2, msg3, protocol3, sip3, dip3;
	private int sport1, dport1, sport2, dport2, sport3, dport3;
	
	private String streamId = "";
	private String name = "";
	
	//数据库参数
	String driver = "com.mysql.jdbc.Driver";
	String url = "jdbc:mysql://127.0.0.1:3306/snort";
	String user = "root";
	String password = "root";
	PreparedStatement sql;
	Connection conn;
	
	public Result_Bolt(){}
	public Result_Bolt(String nm){
		name_bolt =nm;
	}
	public void declareOutputFields(OutputFieldsDeclarer declarer) {
		// TODO Auto-generated method stub
		declarer.declare(new Fields("timestamp","throughput","countPacket"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}

	public void prepare(Map stormConf, TopologyContext context) {
		//////////////
		try {
			lastTime = System.currentTimeMillis()/1000;
			rpack1 = rpack2 = rpack3 = ppack1 = ppack2 = ppack3 =detect1 =detect2 = detect3 = 0;
			rflow1 = rflow2 = rflow3 = pflow1 = pflow2 = pflow3 = 0;
			rtime1 = ptime1 = rtime2 = ptime2 = rtime3 = ptime3 = 0;
			protocol1 = sip1 = dip1 = protocol2 = sip2 = dip2 = protocol3 = sip3 = dip3 = "";
			sport1 = dport1 = sport2 = dport2 = sport3 = dport3 = -1;			
			//连接数据库
			Class.forName(driver);
			conn = DriverManager.getConnection(url,user,password);
			if(conn.isClosed()) {
				System.out.println("can not connect to the db");
			}
			else{
				System.out.println("connect to the db");
			}
		
		}catch (ClassNotFoundException e) {
			e.printStackTrace();		
		} catch (SQLException e) {
			System.out.println("MySQL操作错误");
			e.printStackTrace();
		}
		
	}

	public void execute(Tuple tuple, BasicOutputCollector collector) {
		// TODO Auto-generated method stub
		outputCollector = collector;
		outputCollector.setContext(tuple);   	
		streamId = tuple.getSourceStreamId();
		name = tuple.getSourceComponent();

		try {
			if(name.equals("RuleBolt1")) {
				if(streamId.equals("result")){
					rpack1 = (Integer)tuple.getValueByField("packnum");
					rflow1 = (Long)tuple.getValueByField("flow")*8;//转化成bit
					rtime1 = (Long)tuple.getValueByField("time");
				}
				else if(streamId.equals("result2")){
					ppack1 = (Integer)tuple.getValueByField("packnum");
					detect1 = (Integer)tuple.getValueByField("detect");
					//System.out.println("the received detect1 is:"+detect1);
					pflow1 = (Long)tuple.getValueByField("flow")*8;//转化成bit
					ptime1 = (Long)tuple.getValueByField("time");				
				}
				else if(streamId.equals("detail")) {
					protocol1 = (String)tuple.getValueByField("protocol");
					sip1 = (String)tuple.getValueByField("sip");
					dip1 = (String)tuple.getValueByField("dip");
					sport1 = (Integer)tuple.getValueByField("sport");
					dport1 = (Integer)tuple.getValueByField("dport");
					
					sql = conn.prepareStatement("INSERT INTO detail VALUES(?,?,?,?,?)");
					//要执行的SQL语句
					sql.setString(1, protocol1);
					sql.setString(2, sip1);
					sql.setInt(3, sport1);
					sql.setString(4, dip1);
					sql.setInt(5, dport1);
					sql.executeUpdate();
					return;					
				}			
			}
			else if(name.equals("RuleBolt2")) {
				if(streamId.equals("result")){
					rpack2 = (Integer)tuple.getValueByField("packnum");
					rflow2 = (Long)tuple.getValueByField("flow")*8;//转化成bit
					rtime2 = (Long)tuple.getValueByField("time");
				}
				else if(streamId.equals("result2")){
					ppack2 = (Integer)tuple.getValueByField("packnum");
					detect2 = (Integer)tuple.getValueByField("detect");
					//System.out.println("the received detect1 is:"+detect1);
					pflow2 = (Long)tuple.getValueByField("flow")*8;//转化成bit
					ptime2 = (Long)tuple.getValueByField("time");				
				}
				else if(streamId.equals("detail")) {
					protocol2 = (String)tuple.getValueByField("protocol");
					sip2 = (String)tuple.getValueByField("sip");
					dip2 = (String)tuple.getValueByField("dip");
					sport2 = (Integer)tuple.getValueByField("sport");
					dport2 = (Integer)tuple.getValueByField("dport");					
					sql = conn.prepareStatement("INSERT INTO detail VALUES(?,?,?,?,?)");
					//要执行的SQL语句
					sql.setString(1, protocol2);
					sql.setString(2, sip2);
					sql.setInt(3, sport2);
					sql.setString(4, dip2);
					sql.setInt(5, dport2);
					sql.executeUpdate();
					return;					
				}			
			}
			else if(name.equals("RuleBolt2")) {
				if(streamId.equals("result")){
					rpack2 = (Integer)tuple.getValueByField("packnum");
					rflow2 = (Long)tuple.getValueByField("flow")*8;//转化成bit
					rtime2 = (Long)tuple.getValueByField("time");
				}
				else if(streamId.equals("result2")){
					ppack2 = (Integer)tuple.getValueByField("packnum");
					detect2 = (Integer)tuple.getValueByField("detect");
					//System.out.println("the received detect1 is:"+detect1);
					pflow2 = (Long)tuple.getValueByField("flow")*8;//转化成bit
					ptime2 = (Long)tuple.getValueByField("time");				
				}
				else if(streamId.equals("detail")) {
					protocol3 = (String)tuple.getValueByField("protocol");
					sip3 = (String)tuple.getValueByField("sip");
					dip3 = (String)tuple.getValueByField("dip");
					sport3 = (Integer)tuple.getValueByField("sport");
					dport3 = (Integer)tuple.getValueByField("dport");					
					sql = conn.prepareStatement("INSERT INTO detail VALUES(?,?,?,?,?)");
					//要执行的SQL语句
					sql.setString(1, protocol3);
					sql.setString(2, sip3);
					sql.setInt(3, sport3);
					sql.setString(4, dip3);
					sql.setInt(5, dport3);
					sql.executeUpdate();
					return;					
				}			
			}
	    	
	    	int whole_detect = detect1 + detect2 + detect3;
	    	int whole_pack = ppack1 + ppack2 + ppack3;
	    	int whole_flow = (int)(pflow1 +pflow2 + pflow3);
	    	//输出到数据库
			sql = conn.prepareStatement("INSERT INTO effciency VALUES(?,?,?)");
			//要执行的SQL语句
			sql.setInt(1, whole_detect);
			sql.setInt(2, whole_pack);
			sql.setInt(3, whole_flow);
			sql.executeUpdate();
	    	
			
		} catch(FailedException e) {
	    	System.out.println("Bolt fail to deal with packet");
	    } catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void cleanup() {
		// TODO Auto-generated method stub
		
	}

}
