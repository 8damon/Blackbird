# Runbooks

## IOCTL Capture (Targeted Pull)

1. Build and install the driver.
2. Build `SleepwalkerSensorCore` and `SleepwalkerClient`.
3. Run: `SleepwalkerClient.exe <pid> handle,memory,thread`
4. Stop with Ctrl+C.

## ETW Capture (Real-Time)

1. Build `SleepwalkerSensorCore` and `SleepwalkerClient`.
2. Run: `SleepwalkerClient.exe <pid|path|launch> handle,memory,thread`.
3. If you only need typed detections, use `SwkStartDetectionEtwSession` in your own consumer.
4. Stop with Ctrl+C.

## Validation Suite

1. Build `SleepwalkerSensorCore` and `SleepwalkerTestSuite`.
2. Run: `SleepwalkerTestSuite.exe`
3. Verify all tests pass.
