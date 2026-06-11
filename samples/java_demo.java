import java.lang.Runtime;

class JavaDemo {
    public void run(String input) {
        Runtime.getRuntime().exec("bash", "-c", input);
    }
}