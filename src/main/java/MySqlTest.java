import java.sql.*;
public class MySqlTest {
	public static void main(String[] args) {
		String driver = "com.mysql.jdbc.Driver";
		String url = "jdbc:mysql://127.0.0.1:3306/snort";
		String user = "root";
		String password = "123456";
		PreparedStatement sql;
		
		
			try {
				Class.forName(driver);
				Connection conn = DriverManager.getConnection(url,user,password);
				if(!conn.isClosed()) {
					System.out.println("Succeeded connecting to the Database");
					//statement用来执行SQL语句
					sql = conn.prepareStatement("INSERT INTO effiency VALUES(?,?,?)");
					//要执行的SQL语句
					sql.setInt(1, 13);
					sql.setInt(2, 14);
					sql.setInt(3, 15);
					sql.executeUpdate();
					
					//结果集
				}
				conn.close();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
		
		}
			
		
	}


