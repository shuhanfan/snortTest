import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import snort.test.Helpers.RuleOption;
import snort.test.Helpers.Rule_Header;

public class test {
	//for test rule filter
	public static void main(String args[]) {
		String s = "9:";
		String[] strs = s.split(":");
		
		System.out.println("len is:"+strs.length);
		for(int i = 0; i < strs.length; i++) {
			System.out.println(strs[i]);
		}
	}

}
