import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.sql.Statement;

@RestController
public class VulnerableController {

    @RequestMapping("/users")
    public String handleRequest(String input) {
        return processInput(input);
    }

    public String processInput(String data) {
        runQuery(data);
        return data;
    }

    private void runQuery(String sql) {
        Statement statement = null;
        statement.execute(sql);
    }
}
