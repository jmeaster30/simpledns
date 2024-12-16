use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::clone::Clone;
use std::io::{Error, ErrorKind, Result};
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};
use std::thread::{current, Builder, JoinHandle};
use std::marker::{Send, Sync};
use std::sync::mpsc::{channel, Receiver, Sender};

use rand::random;
use uuid::Uuid;

#[derive(Clone)]
pub enum WorkerState<U> where U: Clone + Send + Sync {
  Idle,
  Busy,
  Finished(U),
  Dead(Arc<Error>), // TODO wack
}

pub struct Worker<T, U> where T: Clone + Send + Sync, U: Clone + Send + Sync {
  sender: Sender<T>,
  handle: Option<JoinHandle<()>>,
  state: WorkerState<U>,
}

impl<T: Clone + Send + Sync + 'static, U: Clone + Send + Sync + 'static> Worker<T, U> { 
  pub fn new<WorkerFn: Fn(Receiver<T>) -> ControlFlow<Result<U>, ()> + Sync + Send + 'static>(worker_fn: WorkerFn) -> Result<Arc<RefCell<Self>>> {
    let (sender, receiver) = channel();

    let worker = Arc::new(RefCell::new(Self {
      sender,
      handle: None,
      state: WorkerState::Idle,
    }));

    let handle = Builder::new().name(Uuid::new_v4().to_string())
      .spawn(move || {
        let move_receiver = receiver;
        loop {
          worker.borrow_mut().get_mut().set_state(WorkerState::Idle);
          match worker_fn(move_receiver) {
            ControlFlow::Break(result) => match result {
              Ok(value) => {
                worker.borrow_mut().get_mut().set_state(WorkerState::Finished(value.clone()));
                break;
              }
              Err(error) => {
                worker.borrow_mut().get_mut().set_state(WorkerState::Dead(Arc::new(error)));
                break;
              }
            }
            ControlFlow::Continue(_) => {}
          }
        }
      })?;

    worker.borrow_mut().get_mut().set_handle(handle);
    
    Ok(worker.clone())
  }

  pub fn send(&mut self, data: T) -> Result<()> {
    match self.sender.send(data) {
      Ok(_) => {}
      Err(error) => return Err(Error::new(ErrorKind::Other, error)) 
    }
    self.set_state(WorkerState::Busy);
    Ok(())
  }

  pub fn set_state(&mut self, state: WorkerState<U>) {
    self.state = state;
  }

  pub fn set_handle(&mut self, handle: JoinHandle<()>) {
    self.handle = Some(handle)
  }

  pub fn kill(&mut self) {
    todo!()
  }

  pub fn get_state(&mut self) -> WorkerState<U> {
    // this stinks lmao
    match &self.handle {
      Some(handle) if handle.is_finished() => self.wait_join(),
      _ => self.state.clone()
    }
  }

  pub fn wait_join(&mut self) -> WorkerState<U> {
    match self.handle {
      Some(_) => {
        let handle = self.handle.take().unwrap();
        self.handle = None;
        match handle.join() {
          Ok(_) => {}
          Err(_) => {
            self.state = WorkerState::Dead(Arc::new(Error::new(ErrorKind::Other, "Join errored"))); // TODO dont just drop this
          }
        }
      }
      _ => {}
    };
    self.state.clone()
  }
}

pub struct ManagerWorkerPool<T: Clone + Send + Sync, U: Clone + Send + Sync, WorkerBuilder: Fn() -> Result<Arc<RefCell<Worker<T, U>>>>> {
  // configuration
  worker_count: usize,
  kill_timeout_ms: usize,
  worker_builder: Option<WorkerBuilder>,

  // management
  worker_threads: Vec<Arc<RefCell<Worker<T, U>>>>,
}

impl<T: Clone + Send + Sync + 'static, U: Clone + Send + Sync + 'static, WorkerBuilder: Fn() -> Result<Arc<RefCell<Worker<T, U>>>>> ManagerWorkerPool<T, U, WorkerBuilder> { 
  pub fn new(worker_count: usize) -> Self {
    Self {
      worker_count,
      kill_timeout_ms: 20_000, // TODO idk what this should be
      worker_builder: None,
      worker_threads: Vec::new(),
    }
  }

  pub fn set_kill_timeout_ms(&mut self, kill_timeout_ms: usize) {
    self.kill_timeout_ms = kill_timeout_ms;
  }

  pub fn set_worker_builder(&mut self, worker_builder: WorkerBuilder) {
    self.worker_builder = Some(worker_builder);
  }

  // TODO unsure about the worker function return type
  fn spawn_worker(&mut self) -> Result<()> {
    if self.worker_builder.is_none() {
      return Err(Error::new(ErrorKind::NotFound, "Missing worker builder :("))
    }

    let unwrapped_builder = self.worker_builder.as_ref().unwrap();
    self.worker_threads.push(unwrapped_builder()?);
    Ok(())
  }

  fn build_missing_workers(&mut self) -> Result<()> {
    if self.worker_threads.len() >= self.worker_count {
      return Ok(());
    }

    let missing_count = self.worker_count - self.worker_threads.len();
    for _ in 0..missing_count {
      self.spawn_worker()?;
    }

    Ok(())
  }

  fn select_random_worker(&mut self) -> Result<Arc<RefCell<Worker<T, U>>>> {
    for worker in &mut self.worker_threads {
      match worker.borrow().get_mut().get_state() {
        WorkerState::Idle => return Ok(worker.clone()),
        _ => {}
      }
    }
    Err(Error::new(ErrorKind::ConnectionRefused, "All workers in thread pool are busy :("))
  }

  // TODO this should be in a separate thread so we can run multiple thread pools at the same time
  pub fn start_manager<F: Fn() -> ControlFlow<(), T>>(&mut self, manager_fn: F) -> Result<()> {
    loop {
      self.build_missing_workers()?;
      match manager_fn() {
        ControlFlow::Break(_) => break,
        ControlFlow::Continue(data) => {
          match self.select_random_worker() {
            Ok(mut worker) => match worker.borrow().get_mut().send(data.clone()) {
              Ok(_) => continue,
              Err(_) => continue, // TODO need to not just ignore these errors maybe have configurable handlers for these???
            },
            Err(_) => continue, // TODO need to not just ignore these errors maybe have configurable handlers for these???
          }
        }
      }
    }
    for worker in &mut self.worker_threads {
      worker.borrow().get_mut().wait_join();
    }
    Ok(())
  }
}