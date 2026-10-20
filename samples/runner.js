// Sample target #2: a tiny runner-game speed controller.
// PyREA should find: the speed values and the update rule.

const START_SPEED = 6;
const MAX_SPEED = 13;
let currentSpeed = 6;

function updateSpeed(frames) {
  if (currentSpeed < MAX_SPEED) {
    return START_SPEED + frames * 0.001;
  }
  return MAX_SPEED;
}

function resetSpeed() {
  return START_SPEED;
}
