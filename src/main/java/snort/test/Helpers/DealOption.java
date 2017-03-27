package snort.test.Helpers;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DealOption {
	Rule_Header rh;
	byte[] payload;//包含整个包信息
	Packet_Header ph;
	ArrayList<RuleOption > rules;//解析后的规则选项列表
	int detect = 0;
	
	public DealOption(){}
	public DealOption(Rule_Header n_rh, Packet_Header n_ph, int ndetect){
		detect = ndetect;	
		rh = n_rh;
		ph = n_ph;
		payload = n_ph.payload;
		//ruleBoltType = n_ruleBoltType;
	/*	try {
			fw = new FileWriter("//opt//res4Snort//DetailDetect",true);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
	}

	 
	 public static boolean isModifier(String key) {
		 Pattern p = Pattern.compile("http_*");
		 Matcher m = p.matcher(key);
		 if(m.find()||key.equals("nocase")||key.equals("rawbytes")||key.equals("depth")||key.equals("offset")||key.equals("distance")||key.equals("within")){
			 return true;
		 }
		 return false;
		 
	 }
	 
	 public static boolean hasModifier(Map<String, String> map) {
		 for(Iterator it =  map.keySet().iterator(); it.hasNext(); ) {		 
			 String key = it.next().toString();
			 if(isModifier(key))
				 return true;
		 }
		 return false;	 
	 }
	 
	 public static String BytetoHexString (byte[] a,int length)//将byte数组转化为16进制字符串
		{
			String cer="";
			for(int i=0;i<length;i++)
			{
				String hex=Integer.toHexString(a[i] & 0xFF);
				if(hex.length()==1){
         		hex ='0'+hex;
         	}
					cer=cer+hex;

			}
			return cer;
		}
	 
	 public static void get_next(String par,int next[]){
			int i=0;
			next[0]=-1;
			int j=-1;
			int par_len = par.length();
			
			for(;i<par_len;){
				if(j==-1||par.charAt(i)==par.charAt(j)){
					i++;
					j++;
					if(i<par_len){
						if(par.charAt(i)==par.charAt(j)) next[i]=next[j];
						else next[i]=j; 
					}			
				}
				else
					j=next[j];
			}
		}

	 
	 public static boolean IndexKMP(String ori, String par, int nk,Map<Integer,ArrayList<Integer> > res,int isStr) {
		 int i=0;
		 int j=0;
		 int st = i;
		 int par_len = par.length();
		int amount = 0;
		ArrayList<Integer> v = new ArrayList<Integer>(50);
		int[] next = new int[par_len];
		get_next(par,next);
		
		while(i>=0&&i<ori.length()&&j>=0&&j<par.length()){
			//System.out.println("in kmp match");
			
			if(j==-1||ori.charAt(i)==par.charAt(j)) {
				i++;
				j++;
			}
			else j=next[j];	
			if(j==par_len) {
				amount++;
				
				if(isStr==1)
					v.add(i-j);
				else
					v.add((i-j)/2);
					
				i=i-j+1;
				j=0;
				
			}

		}
		
		res.put(nk, v);
		if(amount==0) return false;
		return true;

		 
	 }
	 
	 public  boolean KMP(String value,byte[] payload,int nk,Map<Integer,ArrayList<Integer> > res,int ignoreCase) {
	try{
		//fw.write("in KMP\n");
		 String oris;
		 value = value.substring(1, value.length()-1);
		 byte[] app = new byte[payload.length];
	
		 
		 //选出原串和匹配串
		 
		 String[] pat = value.split("\\|");
		 //System.out.println("hha the value is:"+value);
		 //System.out.println(pat.length);
		 oris = new String(payload,"utf-8");
		 
		
		 String orib = BytetoHexString(payload,payload.length);
		 //System.out.println("the orib is:"+orib);
		// System.out.println("the oris is:"+oris);
		 //如果含有byte模式串，进行kmp算法匹配，否则是正常匹配
		 
		 if(pat.length==1){//只有字符串匹配
			 //System.out.println("pat1");
			 //return true;
			 return IndexKMP(oris,pat[0],nk,res,1);
		 }
		 else if(pat.length==2&&pat[0].equals("")){//只有二进制匹配
			 //System.out.println("pat2");
			// return true;
			 return IndexKMP(orib,pat[1],nk,res,0);
			 
		 }
		else{
			//System.out.println("pat3");
			if(IndexKMP(orib,pat[1],nk,res,0)){
				//System.out.println("IndexKMP match!!");
				 ArrayList<Integer> re = res.get(nk);//re是第nk个content匹配的位置集
				 for(int i=0; i<re.size(); ){
					 if(!pat[0].equals("")){
						 if(re.get(i)-pat[0].length()>=0){
							 String tmp = oris.substring(re.get(i)-pat[0].length(),re.get(i));
							 if(tmp.equals(pat[0])){
								 re.set(re.get(i)-pat[0].length(), i);
							 }
							 else{
								 re.remove(i);
								 continue;
							 }
							 
							 
						 }
						 else{
							 re.remove(i);
							 continue;
						 }
						 
					 }
					 for(int j=2; j<pat.length; j++){
						 String p = pat[j];
						 int newstart = re.get(i)+pat[1].length();
						 if(j%2==1){
							 if(newstart*2+p.length()>orib.length()){
								 re.remove(i);
								 continue;
							 }
							 String tmp = orib.substring(newstart*2, newstart*2+p.length());
							 if(!tmp.equals(p)){
								 re.remove(i);
								 continue;
							 }
							 else{
								 newstart += p.length()/2;
							 }
						 }
						 else{
							 if(newstart+p.length()>oris.length()){
								 re.remove(i);
								 continue;
							 }
							 String tmp = orib.substring(newstart, newstart+p.length());
							 if(!tmp.equals(p)){
								 re.remove(i);
								 continue;
							 }
							 else{
								 newstart += p.length();
							 }
							 
						 }
					 }
					 i++;
				 }
				 //System.out.println("re.size():"+re.size());
				 if(re.size()==0) return false;
				 return true;
			 }
			else return false;
		 }
		 
	} catch (UnsupportedEncodingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}catch(IOException e){
		e.printStackTrace();
	}
	return true;	 
	}
	 

	 
	 
	 public void Detect(RuleOption ro, byte[] payload){
			for(Iterator it = ro.headMap.keySet().iterator(); it.hasNext();) {
				 String  key=it.next().toString();    
			     String value=ro.headMap.get(key);
			    // fw.write(key+":"+value+"\n");	//用keyvalue与content无关来处理packet
			     if(key.equals("fragoffset")){
			    	 if(key.contains("!")) {
			    		 if(ph.fragoffset == Integer.parseInt(value.substring(1)))
			    			 return;
			    	 }
			    	 else if(key.contains(">")) {
			    		 if (ph.fragoffset <= Integer.parseInt(value.substring(1)) )
			    			 return;
			    	 }
			    	 else if(key.contains("<")) {
			    		 if(ph.fragoffset >= Integer.parseInt(value.substring(1)))
			    			 return;
			    	 }
			    	 else if (ph.fragoffset != Integer.parseInt(value))
			    		 return;
			     }
			     else if (key.equals("ttl")) {
			    	 if(value.contains("<=")) {
			    		 if(ph.ttl > Integer.parseInt(value.substring(2)))
			    			 return;	    		 
			    	 }
			    	 else if(value.contains(">=")) {
			    		 if(ph.ttl < Integer.parseInt(value.substring(2)))
			    			 return;	 
			    	 }
			    	 else if(value.contains("<")) {
			    		 if(ph.ttl >= Integer.parseInt(value.substring(1)))
			    			 return;	    		 
			    	 }
			    	 else if(value.contains(">")) {
			    		 if(ph.ttl <= Integer.parseInt(value.substring(1)))
			    			 return;	    		 
			    	 }
			    	 else if(value.contains("=")) {
			    		 if(ph.ttl != Integer.parseInt(value.substring(1)))
			    			 return;	    		 
			    	 }
			    	 else if( value.contains("-")) {
			    		 String[] vals = value.split("-");
		    			 if(vals.length == 1) {// 5-
		    				 if(ph.ttl < Integer.parseInt(value.substring(0, 1)))
				    			 return;
		    			 }
		    			 else {//lenth = 2
		    				 if("".equals(vals[0])) {//-5
		    					 if(ph.ttl > Integer.parseInt(vals[1]))
		    						 return;	    					 
		    				 }
		    				 else {//3-5
		    					 if(ph.ttl < Integer.parseInt(vals[0]) || ph.ttl > Integer.parseInt(vals[1]))
		    						 return;
		    				 }		    				 
		    			 }			    		 			    		 
			    	 }
			    	 else {//5
			    		 if(ph.ttl != Integer.parseInt(value))
			    			 return;			    		 
			    	 }
			     }
			     else if(key.equals("tos")) {
			    	 if(value.contains("!")) {
			    		 if(ph.tos == Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }	    		 
			    	 }
			    	 else if(!value.equals(ph.tos+"")){
			    		 return;
			    	 }
			    		
			     }
			     else if(key.equals("id")) {
			    	 if(!value.equals(ph.id+""))
			    		 return;
			     }
			     
			     else if(key.equals("fragbits")){//format is <MDR+>
			    	 if(value.contains("!")){
			    		 if(value.contains("M")&&ph.MF==1)
			    			 return;
			    		 if(value.contains("R")&&ph.Reserved==1)
			    			 return;
			    		 if(value.contains("D")&&ph.DF==1)
			    			 return;
			    	 }
			    	 else if(value.contains("*")){
			    		 if(!(value.contains("M")&&ph.MF==1||value.contains("D")&&ph.DF==1||value.contains("R")&&ph.Reserved==1))
			    			 return;
			    	 }
			    	 else if(value.contains("+")){
			    		 if((value.contains("M")&&ph.MF!=1||value.contains("D")&&ph. DF!=1||value.contains("R")&&ph. Reserved!=1))
			    			 return;
			    	 }
			     }
			     else if (key.equals("ip_proto")){
			    	 String pro = Integer.toString(ph.ip_proto);
			    	 if(!value.equals(pro))
			    		 return;
			    	 
			     }
			     else if (key.equals("ack")){
			    	 String ack = Long.toString(ph.ip_proto);
			    	 if(!value.equals(ack))
			    		 return;
			    	 
			     }
			     else if(key.equals("dsize")){
			    	 String size = Integer.toString(ph.ip_proto);
			    	 if(!value.equals(size))
			    		 return;
			    	 
			     }
			     else if(key.equals("flags")){//CEUAPRSF,可以用12表示CE
			    	 if(value.contains(",")) {
			    		 value = value.split(",")[0];
			    	 }
			    	 //先解析出为true的字符
			    	 int flags = ph.flags;
			    	 String a = "";
			    	 boolean F = false;
			    	 boolean S = false;
			    	 boolean R = false;
			    	 boolean P = false;
			    	 boolean A = false;
			    	 boolean U = false;
			    	 boolean E = false;
			    	 boolean C = false;
			    	 if((flags & 1) == 1) F = true;
			    	 if((flags & 2) == 1) S = true;
			    	 if((flags & 4) == 1) R = true;
			    	 if((flags & 8) == 1) P = true;
			    	 if((flags & 16) == 1) A = true;
			    	 if((flags & 32) == 1) U = true;
			    	 if((flags & 64) == 1) E = true;
			    	 if((flags & 128) == 1) C = true;
			    	
			    	 if(value.contains("!")){
			    		 if(value.contains("F")&&F)
			    			 return;
			    		 if(value.contains("S")&&S)
			    			 return;
			    		 if(value.contains("R")&&R)
			    			 return;
			    		 if(value.contains("P")&&P)
			    			 return;
			    		 if(value.contains("A")&&A)
			    			 return;
			    		 if(value.contains("U")&&U)
			    			 return;
			    		 if((value.contains("E") || value.contains("2"))&&E)
			    			 return;
			    		 if((value.contains("C")|| value.contains("1"))&&C)
			    			 return;
			    	 }
			    	 else if(value.contains("*")) {
			    		 if(!(value.contains("F")&&F || value.contains("S")&&S || value.contains("R")&&R || value.contains("P")&&P || value.contains("A")&&A || value.contains("U")&&U || (value.contains("E")||value.contains("2"))&&E || (value.contains("C") || value.contains("1"))&&C ))
			    			 return;
			    	 }
			    	 else if(value.contains("+")) {
			    		 if((value.contains("F")&&!F || value.contains("S")&&!S || value.contains("R")&&!R || value.contains("P")&&!P || value.contains("A")&&!A || value.contains("U")&&!U || (value.contains("E")||value.contains("2"))&&!E || (value.contains("C") || value.contains("1"))&&!C ))
			    			 return;
			    	 }
			    	 
			    	 
			     }
			     else if(key.equals("seq")) {
			    	 if(!value.equals(ph.seq+""))
			    		 return;    	 
			     }
			     else if(key.equals("ack")){
			    	 if(!value.equals(ph.ack+""))
			    		 return;
			    	 
			     }
			     else if(key.equals("window")){
			    	 if(value.contains("!")) {
			    		 if(ph.window == Integer.parseInt(value.substring(1))){
			    			 return;
			    		 }	    		 
			    	 }
			    	 else if(!value.equals(ph.window+"")){
			    		 return;
			    	 }
			    	 
			     }
			     else if(key.equals("sameip")) {
			    	 if(!ph.sameip)
			    		 return;	    	 
			     }	     
			 }
			
			
			 Map<Integer,ArrayList<Integer> > res;
			 res = new HashMap<Integer,ArrayList<Integer> > (20);
			 int ro_conMap_size = ro.conMap.size();
			for(int k=0; k<ro_conMap_size; k++){
				Map<String,String> tmp = ro.conMap.get(k);//每个tmp都是一个content和modifier小分队集合
				//表示存入的结果集的key
				
				int ignoreCase = 0;
				if(tmp.containsKey("nocase")){
					ignoreCase = 1;
				}
				String value=tmp.get("content");
				//System.out.println(x);
				if(!KMP(value,payload,k,res,ignoreCase))
		    		 return;				 
				 
			}
			
			//开始检验content modifier的值
			for(int k=0; k<ro.conMap.size(); k++){
				Map<String,String> tmp = ro.conMap.get(k);//每个tmp都是一个content和modifier小分队集合
				ArrayList<Integer> mat = ( ArrayList<Integer>) res.get(k);//每个option中一个content的匹配结果
				int nk = 1;
				int within = 0;
				int offset = 0;
				int depth = 0;
				int distance = 0;
				String pattern = tmp.get("content");
				if(tmp.containsKey("within"))
					within = Integer.parseInt(tmp.get("within"));
				if(tmp.containsKey("depth"))
					depth = Integer.parseInt(tmp.get("depth"));
				if(tmp.containsKey("distance"))
					distance = Integer.parseInt(tmp.get("distance"));
				if(tmp.containsKey("offset"))
					offset = Integer.parseInt(tmp.get("offset"));
				for(int h=0; h<mat.size(); )	{
				//for(Iterator<Integer> it = mat.iterator(); it.hasNext();){
					//int h = it.next();
					if(mat.get(h)>offset&&mat.get(h)+pattern.length()-1<=depth+offset) {
					//if(h>offset&&h+pattern.length()-1<=depth+offset){
					    boolean isOk = false;
					    ArrayList<Integer> lastmat;
						if(distance!=0){
							lastmat = (ArrayList<Integer>) res.get(k-1);
							int lastmat_size = lastmat.size();
							for(int j=0; j<lastmat_size; j++){
								if(lastmat.get(j)+distance<=mat.get(h))
									isOk=true;									
							}
							if(!isOk){
								mat.remove(h);
								if(mat.size()==0)
									return;
								continue;
							}
							
							
								//要把该mat的偏移删除，如果mat为空，则return！！
						}
						isOk=false;
						if(within!=0){
							lastmat = ( ArrayList<Integer>) res.get(k-1);
							int lastmat_size = lastmat.size();
							for(int j=0; j<lastmat_size; j++){
								if(lastmat.get(j)+distance+within>=mat.get(h)+pattern.length()-1)
									isOk=true;									
							}
							if(!isOk){
								mat.remove(h);
								if(mat.size()==0)
									return;
								continue;
								
							}
								
						}
						h++;
						
					}
					else return ;
				}
			}
			detect++;
			/*
	      fw.write("the rule is:"+ro.headMap.get("msg")+" "+rh.sip+" "+rh.sport+" "+rh.dip+" "+rh.dport+" "+rh.protocol+"\n");
	      fw.write("the pack is:"+ph.sip+" "+ph.sport+" "+ph.dip+" "+ph.dport+" "+ph.protocol+"\n");
	      fw.write(BytetoHexString(ph.payload,ph.payload.length)+"\n");
	      fw.write("the bolt is:" +  ruleBoltType+"\n\n\n");
			fw.write("\n\n"+"intrusion amount is:"+detect+"\n\n");
			fw.flush();
			System.out.println("intrusion detect!!");
		}catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
			 
			 
		 
		
	 }
	
	public int run(){
		rules = rh.parsed_rule_option;
		for(int i=0; i<rules.size(); i++){//遍历规则选项链表，检测数据包
			RuleOption ro =rules.get(i);
			Detect(ro, payload);			
		}
		return detect;
		/*
		//打印一下规则
		
		
			for(int i=0; i<rules.size(); i++){//遍历规则选项链表，检测数据包
				RuleOption ro =rules.get(i);
				Detect(ro, payload);
				System.out.println("after detect");
				
			}*/
			
			
		
			
	}
	
	

}
