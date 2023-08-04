@FunctionalInterface
public interface IAction {
    boolean execute(String name); // 方法签名要与step系列方法的一样
}
