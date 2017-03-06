const int glitch_pin = 4;
void setup() {
  Serial.begin(19200);
  pinMode(glitch_pin, OUTPUT);
  digitalWrite(glitch_pin, LOW);
}

int loop_count = 0;

void loop() {
  int sleep_time;
  int pulse_count = 10;
  int pulse_len = 3;
  int pulse_pause = 50;
  // Solution ROM

  // Example ROM
  long min_pause = 9800;
  long max_pause = 10000;
  
  int x = 0;
  sleep_time = min_pause + loop_count; // puts it near the start of 'Authorization failed'
  
  while (1) {
    // Reset board
    digitalWrite(glitch_pin, HIGH);
    delayMicroseconds(1000);
    digitalWrite(glitch_pin, LOW);
    delay(1000);
    // Write the good firmware
    Serial.write("05000a0d0400206401000500657404006365010005006e6e04006f6301000500207404006f6e01000500207204006f73010005006e6504007320010005005d5204004f5201000500524504005b20010005003a65040072750100050074610400726501000500706d0400657401000500207404006e650100050072720400754301000306041000340120000016141800260000001400256706201c200430000108030913140023000000000000000000b2b79ddf74e033ff037e81c1bddc349e");
    Serial.flush();
    Serial.write("\n");

    // Wait a bit so we are inside the execution of the program and no longer in the checksum function
    delay(12);

    // Now do a sleep before the glitch
    delayMicroseconds(sleep_time);
    // Next sleep time will be 50 microseconds longer
    sleep_time += 50;

    // Glitch
    cli();
    for (x=0; x< pulse_count; x++) {
      PORTD |= 0x10; // Switch on pin 4
      __builtin_avr_delay_cycles(pulse_len); // glitch length
      PORTD &= 0xEF; // Switch off pin4
      __builtin_avr_delay_cycles(pulse_pause);
    }
    sei();

    // Keep sending some enters and sleeping
    // to allow detection of debugger and allow switching
    // serial from Arduino back to PC
    for (x=0; x< 10; x++) {
        delay(500);
        Serial.write("\n");
    }
    
    if (sleep_time > max_pause) {
      break; // restart
    }
  }
  loop_count += 1;
}
