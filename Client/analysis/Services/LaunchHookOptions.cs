namespace BlackbirdInterface
{
    internal readonly struct LaunchHookOptions
    {
        public LaunchHookOptions(bool useUsermodeHooks, bool useEarlyBirdApcLaunch)
        {
            UseUsermodeHooks = useUsermodeHooks;
            UseEarlyBirdApcLaunch = useEarlyBirdApcLaunch;
        }

        public bool UseUsermodeHooks { get; }
        public bool UseEarlyBirdApcLaunch { get; }

        public static LaunchHookOptions Capture(bool? useUsermodeHooksChecked, bool? earlyBirdChecked,
                                                bool allowEarlyBird)
        {
            bool useUsermodeHooks = useUsermodeHooksChecked == true;
            bool useEarlyBirdApcLaunch = useUsermodeHooks && allowEarlyBird;
            return new LaunchHookOptions(useUsermodeHooks, useEarlyBirdApcLaunch);
        }
    }
}
