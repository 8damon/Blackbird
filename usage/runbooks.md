# Runbooks

## IOCTL Capture (Targeted Pull)

1. Build and install the driver.
2. Build `BlackbirdSensorCore` and `BlackbirdClient`.
3. Run: `BlackbirdClient.exe <pid> handle,memory,thread`
4. Stop with Ctrl+C.

## ETW Capture (Real-Time)

1. Build `BlackbirdSensorCore` and `BlackbirdClient`.
2. Run: `BlackbirdClient.exe <pid|path|launch> handle,memory,thread`.
3. If you only need typed detections, use `SwkStartDetectionEtwSession` in your own consumer.
4. Stop with Ctrl+C.

## Validation Suite

1. Build `BlackbirdSensorCore` and `BlackbirdTestSuite`.
2. Run: `BlackbirdTestSuite.exe`
3. Verify all tests pass.

