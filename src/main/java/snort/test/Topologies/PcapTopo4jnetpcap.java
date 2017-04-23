
package snort.test.Topologies;
import java.util.HashMap;

import snort.test.Spouts.*;
import snort.test.Bolts.*;
import backtype.storm.Config;
import backtype.storm.LocalCluster;
import backtype.storm.StormSubmitter;
import backtype.storm.generated.AlreadyAliveException;
import backtype.storm.generated.InvalidTopologyException;
import backtype.storm.topology.TopologyBuilder;
import backtype.storm.tuple.Fields;
import backtype.storm.utils.Utils;


public class PcapTopo4jnetpcap {
	public static void main(String[] args) {
		TopologyBuilder builder = new TopologyBuilder();
		 Config conf = new Config();
		 if (args == null || args.length == 0) {
			 conf.put("storm.zookeeper.port", 2000);	
			 builder.setSpout("RuleSpout", new Rule_Spout(), 1);
			 builder.setSpout("VolumeSpout", new Volume_Spout(null,-1,null,null,null,-1,"topic2"), 1);
			 builder.setBolt("TransferBolt", new Transfer_Bolt(),1).allGrouping("VolumeSpout","volume").allGrouping("RuleSpout","switch");
			 builder.setBolt("RuleBolt1", new Rule_Bolt("RuleBolt1"),1).allGrouping("RuleSpout","rule").allGrouping("TransferBolt");
			 builder.setBolt("RuleBolt2", new Rule_Bolt("RuleBolt2"),1).shuffleGrouping("RuleSpout","rule").allGrouping("TransferBolt");
			 builder.setBolt("RuleBolt3", new Rule_Bolt("RuleBolt3"),1).shuffleGrouping("RuleSpout","rule").allGrouping("TransferBolt");
			 //-builder.setBolt("RuleTest", new RuleTest(),1).allGrouping("RuleSpout","rule");//测试ruleSpout
			 //-builder.setBolt("VolumnTest", new VolumnTest(),1).allGrouping("VolumeSpout","volume");//测试volumeSpout

			//-- builder.setBolt("ResultBolt", new Result_Bolt(),1).allGrouping("RuleBolt1").allGrouping("RuleBolt2").allGrouping("RuleBolt3");
			 //builder.setBolt("RuleBolt1", new Rule_Bolt("RuleBolt1"),1).allGrouping("VolumeSpout","volume");
			 //builder.setSpout("PcapSpout4jnetpcap1", new PcapSpout4jnetpcap(null,-1,null,null,null,-1,"topic2"), 1);
			 //builder.setSpout("PcapSpout4jnetpcap2", new PcapSpout4jnetpcap(null,-1,null,"/opt/topology/pcap/temp.pcap",null,-1), 1);
			 //builder.setSpout("PcapSpout4jnetpcap3", new PcapSpout4jnetpcap(null,-1,null,"/opt/topology/pcap/temp.pcap",null,-1), 1);
			 //builder.setBolt("expbolt4jnetpcap", new expbolt4jentpcap(),1).allGrouping("PcapSpout4jnetpcap");
			 //builder.setBolt("BasicThroughputBolt3", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap3","basic");
			 //builder.setSpout("PcapSpout4jnetpcap3", new PcapSpout4jnetpcap(null,-1,null,null,null,-1,"topic17"), 1);
			 //builder.setSpout("PcapSpout4jnetpcap3", new PcapSpout4jnetpcap(null,-1,null,null,null,-1,"topic17"), 1);
			 //builder.setBolt("BasicThroughputBolt3", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap3","basic");
			 //builder.setBolt("LengthDistributionBolt", new LengthDistributionBolt(),1).allGrouping("PcapSpout4jnetpcap1","basic");
			 //builder.setBolt("DistributionBolt", new DistributionBolt(),1).allGrouping("PcapSpout4jnetpcap1","basic");
			 //builder.setBolt("BasicThroughputBolt2", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap2","basic");
			 //builder.setBolt("BasicThroughputBolt3", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap3","basic");
			 //builder.setBolt("RedisBolt", new RedisBolt(),1).allGrouping("BasicThroughputBolt1");
			 //builder.setBolt("DistributionBolt", new DistributionBolt(),1).allGrouping("PcapSpout4jnetpcap","basic");
			 conf.setNumWorkers(7);
			 LocalCluster cluster = new LocalCluster();
			 cluster.submitTopology("PcapTopo4jnetpcap", conf, builder.createTopology()); 
			
		     Utils.sleep(1000000);
			 cluster.killTopology("PcapTopo4jnetpcap");
			 cluster.shutdown();
		 }
		 else{
//			 builder.setSpout("RuleSpout", new Rule_Spout(), 1);
//			 builder.setBolt("RuleBolt1", new Rule_Bolt("RuleBolt1"),1).shuffleGrouping("RuleSpout","rule").allGrouping("TransferBolt");
//			 builder.setBolt("RuleBolt2", new Rule_Bolt("RuleBolt2"),1).shuffleGrouping("RuleSpout","rule").allGrouping("TransferBolt");
//			 builder.setBolt("RuleBolt3", new Rule_Bolt("RuleBolt3"),1).shuffleGrouping("RuleSpout","rule").allGrouping("TransferBolt");
//			 builder.setSpout("VolumeSpout", new Volume_Spout(null,-1,null,null,null,-1,"topic15"), 1);
//			 builder.setBolt("TransferBolt", new Transfer_Bolt(),1).allGrouping("VolumeSpout","volume").allGrouping("RuleSpout","switch");
//			 builder.setBolt("ResultBolt", new Result_Bolt(),1).allGrouping("RuleBolt1").allGrouping("RuleBolt2").allGrouping("RuleBolt3");
//			 
			 builder.setSpout("RuleSpout", new Rule_Spout(), 1);
			 builder.setSpout("VolumeSpout", new Volume_Spout(null,-1,null,null,null,-1,"topic2"), 1);
			 //builder.setBolt("TransferBolt", new Transfer_Bolt(),1).allGrouping("VolumeSpout","volume").allGrouping("RuleSpout","switch");
			 builder.setBolt("RuleBolt1", new Rule_Bolt("RuleBolt1"),1).allGrouping("RuleSpout","rule").shuffleGrouping("VolumeSpout","volume");
			 builder.setBolt("RuleBolt2", new Rule_Bolt("RuleBolt2"),1).allGrouping("RuleSpout","rule").shuffleGrouping("VolumeSpout","volume");
			 builder.setBolt("RuleBolt3", new Rule_Bolt("RuleBolt3"),1).allGrouping("RuleSpout","rule").shuffleGrouping("VolumeSpout","volume");
			 builder.setBolt("ResultBolt", new Result_Bolt(),1).allGrouping("RuleBolt1").allGrouping("RuleBolt2").allGrouping("RuleBolt3");
			
			 
			 //builder.setSpout("PcapSpout4jnetpcap1", new PcapSpout4jnetpcap(null,-1,null,null,null,-1,"topic2"), 1);
			 //builder.setSpout("PcapSpout4jnetpcap2", new PcapSpout4jnetpcap2(null,-1,null,null,null,-1,"topic5"), 1);
			 //builder.setSpout("PcapSpout4jnetpcap3", new PcapSpout4jnetpcap3(null,-1,null,null,null,-1,"topic17"), 1);
			 //builder.setSpout("PcapSpout4jnetpcap4", new PcapSpout4jnetpcap4(null,-1,null,null,null,-1,"topic15"), 1);
			 //builder.setBolt("BasicThroughputBolt1", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap1","basic");
			 //builder.setBolt("BasicThroughputBolt2", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap2","basic");
			 //builder.setBolt("BasicThroughputBolt3", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap3","basic");
			 //builder.setBolt("BasicThroughputBolt4", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap4","basic");
			 
			 //builder.setBolt("PortDistributionBolt", new PortDistributionBolt(),1).allGrouping("PcapSpout4jnetpcap4","transfer");
			 //builder.setBolt("CombineBolt", new CombineBolt(),1).allGrouping("BasicThroughputBolt1").allGrouping("BasicThroughputBolt2");
			 //builder.setBolt("Combine10GbBolt", new Combine10GBBolt(),1).allGrouping("BasicThroughputBolt1").allGrouping("BasicThroughputBolt2").allGrouping("BasicThroughputBolt3").allGrouping("BasicThroughputBolt4");
			 //builder.setBolt("LengthDistributionBolt", new LengthDistributionBolt(),1).allGrouping("PcapSpout4jnetpcap1","basic");
			 //builder.setBolt("DistributionBolt", new DistributionBolt(),1).allGrouping("PcapSpout4jnetpcap1","basic");
			 //builder.setBolt("RedisBolt1", new RedisBolt("first"),1).allGrouping("Combine10GbBolt");
			 //builder.setBolt("RedisBolt2", new RedisBolt("second"),1).allGrouping("BasicThroughputBolt2");
			 //builder.setSpout("PcapSpout4jnetpcap", new PcapSpout4jnetpcap(null,-1,null,null,null,-1), 1);
			 //builder.setBolt("BasicThroughputBolt", new BasicThoughputBolt(),1).allGrouping("PcapSpout4jnetpcap","basic");
			 //builder.setBolt("DistributionBolt", new DistributionBolt(),1).allGrouping("PcapSpout4jnetpcap","basic");
//			 HashMap<String, String> component2Node;
//			 component2Node= new HashMap<String, String>();
//			
//			 component2Node.put("RuleSpout", "special-supervisor1");
//			 component2Node.put("TransferBolt", "special-supervisor1");
//			 
//			 component2Node.put("RuleBolt1", "special-supervisor2");
//		     component2Node.put("ResultBolt", "special-supervisor2");
//		     
//		     component2Node.put("RuleBolt2", "special-supervisor4");
//			 
//			 component2Node.put("RuleBolt3", "special-supervisor4");
//			 component2Node.put("VolumeSpout", "special-supervisor4");
//			 
//			 conf.setNumWorkers(7);
//			 
//			//此标识代表topology需要被调度
//		    conf.put("assigned_flag", "1");
//		    //具体的组件节点对信息
//		    conf.put("design_map", component2Node);
			 conf.setNumWorkers(6);
        	 try{
        		 StormSubmitter.submitTopology(args[0], conf, builder.createTopology());
        	 }catch (InvalidTopologyException e ){
        		 e.printStackTrace();
        	 } catch (AlreadyAliveException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	 
		 }
	   
        
	}
}
