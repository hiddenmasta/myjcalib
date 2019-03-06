package algos;

public abstract class Tools
{
  public static String getDefaultProvider(String[] provider)
  {
    return provider.length == 0 ? "BC" : provider[0];
  }
}
