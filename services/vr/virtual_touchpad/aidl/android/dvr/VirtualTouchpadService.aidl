package android.dvr;

/** @hide */
interface VirtualTouchpadService
{
  /**
   * Generate a simulated touch event.
   *
   * @param x Horizontal touch position.
   * @param y Vertical touch position.
   * @param pressure Touch pressure; use 0.0 for no touch (lift or hover).
   *
   * Position values in the range [0.0, 1.0) map to the screen.
   */
  void touch(float x, float y, float pressure);
}
