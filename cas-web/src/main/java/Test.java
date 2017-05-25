import org.jasig.cas.authentication.handler.DefaultPasswordEncoder;

public class Test {
    public static void main(String[] args) {
        DefaultPasswordEncoder passwordEncoder = new DefaultPasswordEncoder("SHA1");
        System.out.println(passwordEncoder.encode("123"));
    }
}
