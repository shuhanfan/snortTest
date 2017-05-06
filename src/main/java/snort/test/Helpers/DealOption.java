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

/*
 * Depth = 5;表示就在前5个byte里面搜索
offset = 5； 表示忽略前5byte
Distance = 5；表示在前一个匹配结尾处，忽略5个byte
within= 5表示在前一个匹配结尾处的之后5个byte之间匹配
 * */
 
public class DealOption {
	//Rule_Header rh;
	
	//byte[] payload;
	public Packet_Header ph;
	public ArrayList<RuleOption > parsed_rules;//解析后的规则选项列表
	int detect = 0;
	//public static FileWriter fw;
	//public FileWriter fw1;
	public DealOption(){		
	}
	public DealOption(Packet_Header this_ph) {
		ph = this_ph;
		
	}
	public DealOption(Packet_Header this_ph, ArrayList<RuleOption> this_parsed_rules){
		ph = this_ph;
		parsed_rules = this_parsed_rules;
//		try {
//		fw1 = new FileWriter("//opt//res4Snort//detectResult", true);
//	} catch (IOException e) {
//		// TODO Auto-generated catch block
//		e.printStackTrace();
//	}		
}
//	public DealOption(Rule_Header n_rh, Packet_Header n_ph, int ndetect){
//		detect = ndetect;	
//		rh = n_rh;
//		ph = n_ph;
//		payload = n_ph.payload;
//		//ruleBoltType = n_ruleBoltType;
//		try {
//			//fw = new FileWriter("//opt//res4Snort//optionMatch", true);
//			fw1 = new FileWriter("//opt//res4Snort//detectResult", true);
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
//	}

	 
//	 public static boolean isModifier(String key) {
//		 if(key.equals(" nocase")||key.equals(" depth")||key.equals("offset")||key.equals("distance")||key.equals("within") ||key.equals(" isdataat") ||key.equals("pkt_data")){
//			 return true;
//		 }
//		 return false;
//		 
//	 }
//	 
//	 public static boolean hasModifier(Map<String, String> map) {
//		 for(Iterator it =  map.keySet().iterator(); it.hasNext(); ) {		 
//			 String key = it.next().toString();
//			 if(isModifier(key))
//				 return true;
//		 }
//		 return false;	 
//	 }
	 
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
			if(par.equals(" "))
				return;
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

	 
	 public static boolean IndexKMP(String ori, String par, int nk,Map<Integer,ArrayList<Integer> > res,boolean isStr,boolean ignoreCase, boolean negative) {
		int i=0;
		int j=0;
		int st = i;
		if(par.equals(" ")) ignoreCase = false;
		int par_len = par.length();
		//System.out.println("the par_len is:"+par_len);
		int amount = 0;
		ArrayList<Integer> v = new ArrayList<Integer>(50);
		int[] next = new int[par_len];
		get_next(par,next);
		//System.out.println("the ori is:"+ori);
		//System.out.println("the par is:"+par);
		while(i<ori.length()){
			//System.out.println("in kmp match");
			
			if(j==-1||ori.charAt(i)==par.charAt(j) || isStr&&ignoreCase &&String.valueOf(par.charAt(j)).toUpperCase().equals(String.valueOf(par.charAt(j)).toUpperCase())) {
				i++;
				j++;
			}
			else j=next[j];	
			if(j==par_len) {
				
				amount++;
				if(isStr){
					
					v.add((i-j)*2);
				}
					
				else {//以byte为记录偏移的单位
					
					v.add((i-j));
				}
					
					
				i=i-j+1;
				j=0;
				
			}

		} 
		
		res.put(nk, v);
		//System.out.println("the "+nk+" content match offset is:");
//		for(int o=0; o<v.size(); o++){
//			//System.out.println(v.get(o)+",");
//		}
		if(!negative) {
			if(amount==0) return false;
			return true;		
		}
		else {
			if(amount==0) return true;
			return false;
		}
		

		 
	 }
	 
	 public static int KMP(String value,byte[] payload,int nk,Map<Integer,ArrayList<Integer> > res, boolean ignoreCase) {//value是匹配的原串
	try{
		//fw.write("in KMP\n");
		/* msg:"MALWARE-BACKDOOR NetBus Pro 2.0 connection established"; flow:to_client,established; flowbits:isset,backdoor.netbus_2.connect;
	       content:"BN|10 00 02 00|"; depth:6;
	       content:"|05 00|"; depth:2; offset:8;
	       
	       *
	       *
	       *
	       */
		int pattern_len = 0;
		 String oris;
		 //System.out.println("in KMP");
		 boolean negative = false;
		 boolean isString = false;
		 //System.out.println("the value in KMP is:"+value);
		 if(value.charAt(1)=='!') {
			 negative = true;
			 value = value.substring(2,value.length()-1);
		 }
		 else {
			 value = value.substring(1, value.length()-1);
		 }
		 //System.out.println("the value is"+value);
		 byte[] app = new byte[payload.length];
	
		 
		 //选出原串和匹配串
		 
		 String[] pat = value.split("\\|");//一定是 str+byte+str
		 //System.out.println("hha the value is:"+value);
		 //System.out.println(pat.length);
		 oris = new String(payload,"utf-8");
		 
		
		 String orib = BytetoHexString(payload,payload.length);//orib的长度是oris的两倍
		 //System.out.println("the orib is:"+orib);
		// //System.out.println("the oris is:"+oris);
		 //如果含有byte模式串，进行kmp算法匹配，否则是正常匹配
		 
		 if(pat.length==1){//只有字符串匹配
			 //System.out.println("pat1");
			 isString = true;
			 pattern_len = value.length()*2;
			 //return true;
			 if(IndexKMP(oris,pat[0],nk,res,isString,ignoreCase,negative))
				 return pattern_len;
			 else 
				 return 0;
			
			
		 }
		 else if(pat.length==2&&("").equals(pat[0])){//只有二进制匹配
			 //System.out.println("pat2");
			// return true;
			 
			 pat[1]=pat[1].replace(" ", "");
			 pattern_len = pat[1].length();
			 if(IndexKMP(orib,pat[1],nk,res,isString,ignoreCase,negative))
				 return pattern_len;
			 else 
				 return 0;
			 
		 }
		else{
			//System.out.println("pat3");
			//fw.write("in pat3\n");
			pat[1] = pat[1].replace(" ", "");
			
			if(IndexKMP(orib,pat[1],nk,res,isString,ignoreCase,negative)){
				int newstart = -1;
				//System.out.println("IndexKMP match!!");
				int cur_len = 0;
				

				 ArrayList<Integer> re = res.get(nk);//re是第nk个content匹配的位置集
				 for(int i=0; i<re.size(); ){
					 
					 cur_len = pat[1].length();
					 newstart = re.get(i) + pat[1].length();
					 //System.out.println("the newstart is:"+newstart);
					 if(!pat[0].equals("")){
						cur_len += pat[0].length()*2;
						 //System.out.println("the newstart is:"+newstart);
						 //System.out.println("!pat[0].equals null");
						 if(re.get(i)-pat[0].length()*2>=0){
							 //System.out.println("re.get(i)-pat[0].length()*2>=0");
							 String tmp = oris.substring(re.get(i)/2-pat[0].length(),re.get(i)/2);
							 //System.out.println("the tmp is:"+tmp);
							 //System.out.println("the pat[0] is:"+pat[0]);
							 if(tmp.equals(pat[0])){
								 //System.out.println("tmp.equals(pat[0])");
								 //System.out.println("re.get(i) is:"+re.get(i));
								 //System.out.println("pat[0].length() is:"+pat[0].length());
								 re.set(i,re.get(i)-pat[0].length()*2);
							 }
							 else{
								 //System.out.println("!tmp.equals(pat[0])");
								 re.remove(i);
								 if(re.size() == 0){
									 //System.out.println("re.size() == 0");
									 return 0;
								 }
									 
								 continue;
								 
							 }
							 
							 
						 }
						 else{
							 //System.out.println("!re.get(i)-pat[0].length() >=0");
							 re.remove(i);
							 if(re.size() == 0){
								 //System.out.println("re.size() == 0");
								 return 0;
							 }
							 continue;
						 }
						 
					 }
					 //System.out.println("the newstart is:"+newstart);
					 int j = 2;
					 for(; j<pat.length; j++){
						 String p = pat[j];
						 
						 if(j%2==1){//match byte
							 p = p.replace(" ", "");
							 cur_len += p.length();
							 //System.out.println("match byte,the cur_len is:"+cur_len);
							 if(newstart+p.length()>orib.length()){
								 //System.out.println("newstart+p.length()>orib.length()");
								 re.remove(i);
								 if(re.size() == 0){
									 //System.out.println("re.size() == 0");
									 return 0;
								 }
									 
								 break;
							 }
							 String tmp = orib.substring(newstart, newstart+p.length());
							 if(!tmp.equals(p)){
								 //System.out.println("!tmp.equals(p) tmp is:"+tmp+",p is:"+p);
								 re.remove(i);
								 if(re.size() == 0){
									 //System.out.println("re.size() == 0");
									 return 0;
								 }
									 
								 break;
							 }
							 else{
								 //System.out.println("tmp.equals(p)");
								 newstart += p.length();
								 //System.out.println("the newstart is:"+newstart);
							 }
						 }
						 else{//match string
							 
							 cur_len += p.length()*2;
							 //System.out.println("match string,the cur_len is:"+cur_len);
//							 if(p.equals(" ")){
//								 break;
//							 }
							 if(newstart+p.length()*2>orib.length()){
								 //System.out.println("newstart+p.length()*2>orib.length()");
								 re.remove(i);
								 if(re.size() == 0){
									 //System.out.println("re.size() == 0");
									 return 0;
								 }
									 
								 break;
							 }
							 String tmp = oris.substring(newstart/2, newstart/2+p.length());
							 if(ignoreCase) {
								 tmp = tmp.toLowerCase();
								 p = p.toLowerCase();
							 }
								 
							 
							 //System.out.println("the sub oris is:"+tmp);
							 //System.out.println("the match sub str is:"+p);
							 if(!tmp.equals(p)){
								 //System.out.println("!tmp.equals(p)");
								 re.remove(i);
								 if(re.size() == 0){
									 //System.out.println("re.size() == 0");
									 return 0;
								 }
									 
								 break;
							 }
							 else{
								 //System.out.println("tmp.equals(p)");
								 newstart += p.length() * 2;
								 //System.out.println("the new start is:"+newstart);
							 }
							 
						 }
						 
					 }
					 
					 if(j == pat.length) {//the par str match success so check the next , or else because of break and remove a offset,so not need i++ when check the next match
						 //System.out.println("j == pat.length");
						 i++;	
						 
					 }
					 if(cur_len > pattern_len)
						 pattern_len = cur_len;
					 
					 
				 }
				 //System.out.println("re.size():"+re.size());
				 if(re.size()==0) return 0;
				 //System.out.println("the re size is:"+re.size());
//				 for(int i=0; i<re.size(); i++){
//						//System.out.println("the re is"+re.get(i));
//					}
				return pattern_len;
				 
			 }
			else{
				//System.out.println("!IndexKMP(orib,pat[1],nk,res,0)");
				return 0;
			}
			
		 }
		
		 
	} catch (UnsupportedEncodingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return 1;
	 }
	 
	
		 
	
	 

	 
	 
	 public void Detect(RuleOption ro, byte[] payload){
	//	 try{
			 ////fw.write("the rule option is:");
			 //System.out.println("the rule option is:");
//			 for (String key : ro.headMap.keySet()) {
//				   //fw.write(key + ":" + ro.headMap.get(key) + ";");
//				   //System.out.println(key + ":" + ro.headMap.get(key) + ";");
//			}
			 ////fw.write("\n");
			 for ( int n = 0 ; n <ro.conMap.size(); n++){
				 //System.out.println("the n is:"+n);
				 Map<String, String> map = ro.conMap.get(n);
//				 for (String key : map.keySet()) {
//					   ////fw.write(key + ":" + map.get(key) + ";");
//					   //System.out.println(key + ":" + map.get(key) + ";");
//				}
				 ////fw.write("\n");
				 
			 }
			for(Iterator it = ro.headMap.keySet().iterator(); it.hasNext();) {
				 String  key=it.next().toString();    
			     String value=ro.headMap.get(key);
			    // ////fw.write(key+":"+value+"\n");	//用keyvalue与content无关来处理packet
			     if(key.equals(" fragoffset")){
			    	 ////fw.write("in fragoffset:\n");
			    	 //System.out.println("in fragoffset:");
			    	 if(value.contains("!")) {
			    		 if(ph.fragoffset == Integer.parseInt(value.substring(1))){
			    			 ////fw.write("! and equal\n");
			    			 //fw.flush();
			    			 //System.out.println("! and equal");
			    			 
			    			 return;

			    		 }
			    			 
			    	 }
			    	 else if(value.contains(">")) {
			    		 if (ph.fragoffset <= Integer.parseInt(value.substring(1)) ){
			    			 ////fw.write("ph <= rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph <= rh\n");
			    			 return;
			    		 }
			    			 
			    	 }
			    	 else if(value.contains("<")) {
			    		 if(ph.fragoffset >= Integer.parseInt(value.substring(1))){
			    			 ////fw.write("ph > rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph > rh");
			    			 return;
			    		 }
			    			 
			    	 }
			    	 else if (ph.fragoffset != Integer.parseInt(value)){
			    		 ////fw.write("ph != rh\n");
			    		 //fw.flush();
			    		 //System.out.println("ph != rh");
			    		 return;
			    	 }
			    		 
			     }
			     else if (key.equals(" ttl")) {
			    	 ////fw.write("in ttl \n");
			    	 //System.out.println("in ttl");
			    	 if(value.contains("<=")) {
			    		 if(ph.ttl > Integer.parseInt(value.substring(2))){
			    			 ////fw.write("ph > rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph > rh");
			    			 return;
			    		 }
			    				    		 
			    	 }
			    	 else if(value.contains(">=")) {
			    		 if(ph.ttl < Integer.parseInt(value.substring(2))){
			    			 ////fw.write("ph < rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph < rh");
			    			 return;
			    		 }
			    			 	 
			    	 }
			    	 else if(value.contains("<")) {
			    		 if(ph.ttl >= Integer.parseInt(value.substring(1))){
			    			 ////fw.write("ph >= rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph >= rh");
			    			 return;
			    		 }
			    				    		 
			    	 }
			    	 else if(value.contains(">")) {
			    		 if(ph.ttl <= Integer.parseInt(value.substring(1))){
			    			 ////fw.write("ph <= rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph <= rh");
			    			 return;
			    		 }
			    				    		 
			    	 }
			    	 else if(value.contains("=")) {
			    		 if(ph.ttl != Integer.parseInt(value.substring(1))){
			    			 ////fw.write("ph != rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph != rh");
			    			 return;
			    		 }
			    			 	    		 
			    	 }
			    	 else if( value.contains("-")) {
			    		 String[] vals = value.split("-");
		    			 if(vals.length == 1) {// 5-
		    				 if(ph.ttl < Integer.parseInt(value.substring(0, 1))){
		    					 ////fw.write("5- and ph < rh\n");
		    					 //fw.flush();
		    					 //System.out.println("5- and ph < rh");
		    					 return;
		    				 }
				    			 
		    			 }
		    			 else {//lenth = 2
		    				 if("".equals(vals[0])) {//-5
		    					 if(ph.ttl > Integer.parseInt(vals[1])){
		    						 ////fw.write("-5 and ph > rh\n");
		    						 //fw.flush();
		    						 //System.out.println("-5 and ph > rh");
		    						 return;
		    					 }
		    							    					 
		    				 }
		    				 else {//3-5
		    					 if(ph.ttl < Integer.parseInt(vals[0]) || ph.ttl > Integer.parseInt(vals[1])){
		    						 ////fw.write("3-5 and ph not in the range\n");
		    						 //fw.flush();
		    						 //System.out.println("3-5 and ph not in the range");
		    						 return;
		    					 }
		    						 
		    				 }		    				 
		    			 }			    		 			    		 
			    	 }
			    	 else {//5
			    		 if(ph.ttl != Integer.parseInt(value)){
			    			 ////fw.write("ph != rh\n");
			    			 //fw.flush();
			    			 //System.out.println("ph != rh");
			    			 return;
			    		 }
			    						    		 
			    	 }
			     }
			     else if(key.equals(" tos")) {
			    	 ////fw.write("in tos:\n");
			    	 //System.out.println("in tos");
			    	 if(value.contains("!")) {
			    		 if(ph.tos == Integer.parseInt(value.substring(1))){
			    			 ////fw.write("! and ph == rh\n");
			    			 //fw.flush();
			    			 //System.out.println("! and ph == rh");
			    			 return;
			    		 }	    		 
			    	 }
			    	 else if(!value.equals(ph.tos+"")){
			    		 ////fw.write("ph != rh\n");
			    		 //fw.flush();
			    		 //System.out.println("ph != rh");
			    		 return;
			    	 }
			    		
			     }
			     else if(key.equals(" id")) {
			    	 //System.out.println("in id:");
			    	 if(!value.equals(ph.id+"")){
			    		 ////fw.write("in id:\n ph != rh\n");
			    		 //fw.flush();
			    		 //System.out.println("ph != rh");
			    		 return;
			    	 }
			    		 
			     }
			     
			     else if(key.equals(" fragbits")){//format is <MDR+>
			    	 ////fw.write("in fragbits:\n");
			    	 //System.out.println("in fragbits:");
			    	 if(value.contains("!")){
			    		 ////fw.write("contains !:");
			    		 //System.out.println("contains !:");
			    		 if(value.contains("M")&&ph.MF==1){
			    			 ////fw.write("MF\n");
			    			 //fw.flush();
			    			 //System.out.println("MF");
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("R")&&ph.Reserved==1){
			    			 ////fw.write("Reserved\n");
			    			 //fw.flush();
			    			 //System.out.println("Reserved");
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("D")&&ph.DF==1){
			    			 ////fw.write("DF\n");
			    			 //fw.flush();
			    			 //System.out.println("DF");
			    			 return;
			    		 }
			    			 
			    	 }
			    	 else if(value.contains("*")){
			    		 if(!(value.contains("M")&&ph.MF==1||value.contains("D")&&ph.DF==1||value.contains("R")&&ph.Reserved==1)){
			    			 ////fw.write("contain *\n");
			    			 //fw.flush();
			    			 //System.out.println("contain *");
			    			 return;
			    		 }
			    			
			    	 }
			    	 else if(value.contains("+")){
			    		 if((value.contains("M")&&ph.MF!=1||value.contains("D")&&ph. DF!=1||value.contains("R")&&ph. Reserved!=1)) {
			    			 ////fw.write("contains +\n");
			    			 //fw.flush();
			    			 //System.out.println("contains +");
			    			 return;
			    		 }
			    			 
			    	 }
			     }
			     else if (key.equals(" ip_proto")){
			    	 String pro = Integer.toString(ph.ip_proto);
			    	 if(!value.equals(pro)){
			    		 ////fw.write("ip_proto not equal\n");
			    		 //fw.flush();
			    		 //System.out.println("ip_proto not equal");
			    		 return;
			    	 }
			    		
			    	 
			     }
			     
			     else if(key.equals(" dsize")){
			    	 //System.out.println("in dsize");
			    	 int dsize = ph.dsize;
			    	 String size = Integer.toString(dsize);
			    	 if(!value.equals(size)){
			    		 ////fw.write("dsize not equal\n");
			    		 //fw.flush();
			    		 if(value.contains("<>")) {
			    			 String[] d = value.split("<>");
			    			 int min = Integer.parseInt(d[0]);
			    			 int max = Integer.parseInt(d[1]);
			    			 if(dsize>max || dsize<min) {
			    				 //System.out.println("not in <> range");
					    		 return;
			    			 }
			    		 }
			    		 else if(value.contains(">")) {
			    			 int min = Integer.parseInt(value.substring(1));
			    			 if( dsize<min) {
			    				 //System.out.println("less than  min");
					    		 return;
			    			 }
			    		 }
			    		 else if(value.contains("<")) {
			    			 int max = Integer.parseInt(value.substring(1));
			    			 if( dsize>max) {
			    				 //System.out.println("larger than max");
					    		 return;
			    			 }
			    		 }
			    		 else{
				    		 //System.out.println("dsize not equal");
				    		 return;
			    		 }
			    	 }
			    		 
			    	 
			     }
			     else if(key.equals(" flags")){//CEUAPRSF,可以用12表示CE
			    	 ////fw.write("in flags: \n");
			    	 //System.out.println("in flags:");
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
			    	 //System.out.println("flag&8 is:"+((ph.flags&8)>>3));
			    	 if((flags & 1) == 1) F = true;
			    	 if((flags & 2)>>1 == 1) S = true;
			    	 if((flags & 4)>>2 == 1) R = true;
			    	 if((flags & 8)>>3 == 1) P = true;
			    	 if((flags & 16)>>4 == 1) A = true;
			    	 if((flags & 32)>>5 == 1) U = true;
			    	 if((flags & 64)>>6 == 1) E = true;
			    	 if((flags & 128)>>7 == 1) C = true;
			    	 //System.out.println(F+","+S+","+R+","+P+","+A+","+U+","+E+","+C);
			    	
			    	 if(value.contains("!")){
			    		 ////fw.write("contains !\n");
			    		 if(value.contains("F")&&F) {
			    			 ////fw.write("F\n");
			    			 //fw.flush();
			    			 //System.out.println("F");
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("S")&&S) {
			    			 ////fw.write("S\n");
			    			 //fw.flush();
			    			 //System.out.println("S");
			    			 return;
			    		 }
			    			
			    		 if(value.contains("R")&&R) {
			    			 ////fw.write("R\n");
			    			 //fw.flush();
			    			 //System.out.println("R");
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("P")&&P) {
			    			 ////fw.write("P\n");
			    			 //fw.flush();
			    			 //System.out.println("P");
			    			 return;
			    		 }
			    			 
			    		 if(value.contains("A")&&A) {
			    			 ////fw.write("A\n");
			    			 //fw.flush();
			    			 //System.out.println("A");
			    			 return;
			    		 }
			    			
			    		 if(value.contains("U")&&U) {
			    			 ////fw.write("U\n");
			    			 //fw.flush();
			    			 //System.out.println("U");
			    			 return;
			    		 }
			    			 
			    		 if((value.contains("E") || value.contains("2"))&&E) {
			    			 ////fw.write("E\n");
			    			 //fw.flush();
			    			 //System.out.println("E");
			    			 return;
			    		 }
			    			
			    		 if((value.contains("C")|| value.contains("1"))&&C) {
			    			 ////fw.write("C\n");
			    			 //fw.flush();
			    			 //System.out.println("C");
			    			 return;
			    		 }
			    			
			    	 }
			    	 else if(value.contains("*")) {
			    		 if(!(value.contains("F")&&F || value.contains("S")&&S || value.contains("R")&&R || value.contains("P")&&P || value.contains("A")&&A || value.contains("U")&&U || (value.contains("E")||value.contains("2"))&&E || (value.contains("C") || value.contains("1"))&&C )) {
			    			 ////fw.write("contains *\n");
			    			 //fw.flush();
			    			 //System.out.println("contains *");
			    			 return;
			    		 }
			    			
			    	 }
			    	 else if(value.contains("+")) {
			    		 if((value.contains("F")&&!F || value.contains("S")&&!S || value.contains("R")&&!R || value.contains("P")&&!P || value.contains("A")&&!A || value.contains("U")&&!U || (value.contains("E")||value.contains("2"))&&!E || (value.contains("C") || value.contains("1"))&&!C )) {
			    			 ////fw.write("contains +\n");
			    			 //fw.flush();
			    			 //System.out.println("contains +");
			    			 return;
			    		 }
			    			
			    	 }
			    	 
			    	 
			     }
			     else if(key.equals(" seq")) {
			    	 if(!value.equals(ph.seq+"")) {
			    		 ////fw.write("seq not equal\n");
			    		 //fw.flush();
			    		 //System.out.println("seq not equal");
			    		 return;
			    	 }
			    		    	 
			     }
			     else if(key.equals(" ack")){
			    	 if(!value.equals(ph.ack+"")) {
			    		 ////fw.write("ack not equal\n");
			    		 //fw.flush();
			    		 //System.out.println("ack not equal");
			    		 return;
			    	 }
			    		
			    	 
			     }
			     else if(key.equals(" window")){
			    	 if(value.contains("!")) {
			    		 if(ph.window == Integer.parseInt(value.substring(1))){
			    			 ////fw.write(" !window and equal\n");
			    			 //fw.flush();
			    			 //System.out.println("!window and equal");
			    			 return;
			    		 }	    		 
			    	 }
			    	 else if(!value.equals(ph.window+"")){
			    		 ////fw.write("window not equal\n");
			    		 //fw.flush();
			    		 //System.out.println("window not equal");
			    		 return;
			    	 }
			    	 
			     }
			     else if(key.equals(" sameip")) {
			    	 if(!ph.sameip) {
			    		 ////fw.write("not sameip\n");
			    		 //fw.flush();
			    		 //System.out.println("not sameip");
			    		 return;
			    	 }
			    			    	 
			     }	     
			 }
			
			
			//开始对payload相关字段进行检测

			Map<Integer,ArrayList<Integer> > res;
			 res = new HashMap<Integer,ArrayList<Integer> > (20);
			 int ro_conMap_size = ro.conMap.size();
			for(int k=0; k<ro_conMap_size; k++){
				int pattern_len = 0;
				Map<String,String> tmp = ro.conMap.get(k);//每个tmp都是一个content和modifier小分队集合
				//表示存入的结果集的key
				
				boolean ignoreCase = false;
				if(tmp.containsKey(" nocase")){
					ignoreCase = true;
				}
				String value=tmp.get(" content");
				////fw.write("the content is:"+value+"\n");
				//System.out.println("");
				pattern_len = KMP(value,payload,k,res,ignoreCase);
				if(pattern_len == 0) {
					//res存储的是第k个content的匹配所有匹配位置，k表示匹配的是第k个content
					////fw.write("!KMP(value,payload,k,res,ignoreCase)\n");
					//fw.flush();
					//System.out.println("!KMP(value,payload,k,res,ignoreCase)");
					 return;
				}
				ro.conMap.get(k).put("pattern_len", Integer.toString(pattern_len));
				//System.out.println("the pattern_len is:"+pattern_len);
		    		 				 
				 
			}
			//System.out.println("start all check content modifiers");
			
			//开始检验content modifier的值
			for(int k=0; k<ro.conMap.size(); k++){
				Map<String,String> tmp = ro.conMap.get(k);//每个tmp都是一个content和modifier小分队集合
				ArrayList<Integer> mat = ( ArrayList<Integer>) res.get(k);//每个option中一个content的匹配结果
				int nk = 1;
				int within = 0;
				int offset = 0;
				int depth = 0;
				int distance = 0;
				int pattern_len = 0;
			
				String pattern = tmp.get(" content");
				
				if(tmp.containsKey(" within"))
					within = Integer.parseInt(tmp.get(" within"));
				if(tmp.containsKey(" depth"))
					depth = Integer.parseInt(tmp.get(" depth"));
				if(tmp.containsKey(" distance"))
					distance = Integer.parseInt(tmp.get(" distance"));
				if(tmp.containsKey(" offset"))
					offset = Integer.parseInt(tmp.get(" offset"));
				pattern_len = Integer.parseInt(tmp.get("pattern_len"));
				//System.out.println("pattern_len is:"+pattern_len);
				for(int h=0; h<mat.size(); )	{
				//for(Iterator<Integer> it = mat.iterator(); it.hasNext();){
					//int h = it.next();
					int pos = mat.get(h);
					//System.out.println("the match pos is:"+pos);
					//System.out.println("the offset is"+offset);
					
					
					
					//注意pos是从0开始算的，但是offset是从1开始的
					if(pos>=offset&&(depth == 0 ||(pos+pattern_len<=depth+offset))) {
					//if(h>offset&&h+pattern.length()-1<=depth+offset){
					    boolean isOk = false;
					    ArrayList<Integer> lastmat;
					  //检测该content匹配位置是否满足distance
						if(distance!=0 && k>0){
							lastmat = (ArrayList<Integer>) res.get(k-1);
							int lastmat_size = lastmat.size();
							for(int j=0; j<lastmat_size; j++){
								//System.out.println("the lastmat is:"+lastmat.get(j));
								//System.out.println("the pos is:"+pos);
								if(lastmat.get(j)+distance<pos){
									//System.out.println("lastmat.get(j)+distance<pos");
									isOk=true;	
									break;
								}
									
							}
							if(!isOk){
								mat.remove(h);
								if(mat.size()==0) {
									////fw.write("distance not match and matsize =0\n");
									//fw.flush();
									//System.out.println("distance not match and matsize =0");
									return;
								}
									
								continue;
							}
							
							
								
						}
						//检测该content匹配位置是否满足within
						isOk=false;
						if(within!=0 && k>0){
							lastmat = ( ArrayList<Integer>) res.get(k-1);
							int lastmat_size = lastmat.size();
							for(int j=0; j<lastmat_size; j++){
								//System.out.println("lastmat is:"+lastmat.get(j));
								//System.out.println("distance is:"+distance);
								//System.out.println("within is:"+within);
								//System.out.println("pos is:"+pos);
								//System.out.println("pattern_len is:"+pattern_len);
								if(lastmat.get(j)+distance+within>=pos+pattern_len-1){
									isOk=true;	
									break;
								}
																	
							}
							if(!isOk){
								mat.remove(h);
								if(mat.size()==0) {
									////fw.write("within not match and matsize =0\n");
									//fw.flush();
									//System.out.println("within not match and matsize =0");
									return;
								}
									
								continue;
								
							}
								
						}
						
						//检测该匹配位置是否满足isdataat
						
						if(tmp.containsKey(" isdataat")) {
							String value = tmp.get(" isdataat");
							
							if(!value.contains("!")){
								String[] vals = value.split(",");
								int far = Integer.parseInt(vals[0]);
								if(vals.length > 1 && vals[1].equals("relative")){
									if(payload.length < pos+pattern.length()+far) {
										mat.remove(h);
										if(mat.size()==0) {
											////fw.write("isdataat relative not match and matsize =0\n");
											//fw.flush();
											//System.out.println("isdataat relative not match and matsize =0");
											return;
										}
											
										continue;
									}
									
								}
								else {
									if(payload.length < far) {
										mat.remove(h);
										if(mat.size()==0) {
											////fw.write("isdataat absolute not match and matsize =0\n");
											//fw.flush();
											//System.out.println("isdataat absolute not match and matsize =0");
											return;
										}
											
										continue;
									}
								}
							}
							
							else{//isdataat:!2,relative
								String[] vals = value.substring(1).split(",");
								int far = Integer.parseInt(vals[0]);
								if(vals.length > 1 && vals[2].equals("relative")){
									if(payload.length >= pos+pattern.length()+far) {
										mat.remove(h);
										if(mat.size()==0) {
											////fw.write("isdataat !2,relatvie not match and matsize =0\n");
											//fw.flush();
											//System.out.println("isdataat !2,relatvie not match and matsize =0");
											return;
										}
											
										continue;
									}
									
								}
								else {
									if(payload.length > far) {
										mat.remove(h);
										if(mat.size()==0) {
											////fw.write("isdataat !2 absolute not match and matsize =0\n");
											//fw.flush();
											//System.out.println("isdataat !2 absolute not match and matsize =0");
											return;
										}
										continue;
									}
								}
								
								
							}
						}
						
						
						//检测该匹配位置是否需要为下一个设置pk_data
						if(tmp.containsKey(" pkt_data")) {
							mat.set(h, 0);
						}
						
						else{
							mat.set(h, pos+pattern_len-1);
						}
						//将匹配起始值更新为匹配终止值
						h++;
						
					}
					else {
						////fw.write("offset and depth not match\n");
						//fw.flush();
						//System.out.println("offset and depth not match");
						return ;
					}
					
					
					//////fw.write("intrusion detect!!");
				   ////fw.write("detect instruction!\n");
				   //System.out.println("a content modifier satisfied!");
				   break;
				}
				
				
				
			}
			detect++;
			//System.out.println("detect instruction!");
//		   fw1.write("detect instruction!\n");
//	       fw1.write("the rule is:"+ro.headMap.get("msg")+" "+rh.sip+" "+rh.sport+" "+rh.dip+" "+rh.dport+" "+rh.protocol+"\n");
//	       fw1.write("the pack is:"+ph.sip+" "+ph.sport+" "+ph.dip+" "+ph.dport+" "+ph.protocol+"\n");
//	       fw1.write(BytetoHexString(ph.payload,ph.payload.length)+"\n");
//	     
//		   fw1.write("\n\n"+"intrusion amount is:"+detect+"\n\n");
//		   fw1.flush();
//		}catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
			 
			 
		 
		
	 }
	
	public int run(){
//		try {
//			////fw.write("in dealOption\n");
//			//fw.flush();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		for(int i=0; i<parsed_rules.size(); i++){//遍历规则选项链表，检测数据包
			RuleOption ro =parsed_rules.get(i);
			Detect(ro, ph.payload);			
		}
		//System.out.println("the detect num is:"+detect);
		return detect;
		/*
		//打印一下规则
		
		
			for(int i=0; i<rules.size(); i++){//遍历规则选项链表，检测数据包
				RuleOption ro =rules.get(i);
				Detect(ro, payload);
				//System.out.println("after detect");
				
			}*/
			
			
		
			
	}
	
	

}
