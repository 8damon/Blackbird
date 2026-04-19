namespace BlackbirdInterface
{
    internal readonly struct LaunchHookOptions
    {
        public LaunchHookOptions(bool useUsermodeHooks, bool autoOpenApiGraphWindow, bool useEarlyBirdApcLaunch)
        {
            UseUsermodeHooks = useUsermodeHooks;
            AutoOpenApiGraphWindow = autoOpenApiGraphWindow;
            UseEarlyBirdApcLaunch = useEarlyBirdApcLaunch;
        }

        public bool UseUsermodeHooks { get; }
        public bool AutoOpenApiGraphWindow { get; }
        public bool UseEarlyBirdApcLaunch { get; }

        public static LaunchHookOptions Capture(bool? useUsermodeHooksChecked, bool? autoOpenApiGraphChecked, bool? earlyBirdChecked, bool allowEarlyBird)
        {
            bool useUsermodeHooks = useUsermodeHooksChecked == true;
            bool autoOpenApiGraphWindow = useUsermodeHooks && autoOpenApiGraphChecked != false;
            bool useEarlyBirdApcLaunch = useUsermodeHooks && allowEarlyBird;
            return new LaunchHookOptions(useUsermodeHooks, autoOpenApiGraphWindow, useEarlyBirdApcLaunch);
        }
    }
}
